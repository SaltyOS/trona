// SPDX-License-Identifier: GPL-2.0-only
//
//! PE file → memory-image layout planner.
//!
//! Both `ldsrv::resolve::relayout_pe` (resolve-time) and
//! `init::ldsrv_adopt::adopt_object_pe` (boot-time cache prewarm) need
//! to translate a PE file's sections from file offsets to RVAs into a
//! fresh memory-image MO. This module owns the **planning** half —
//! header validation, bounds checking, and the (file_off, dst_rva,
//! bytes) copy list — so both callers compose the same correctness
//! invariants without sharing MO/IPC code (which would force the loader
//! crate to pull in mmsrv IPC).
//!
//! Callers back the planner with whatever MO read/write path they own:
//! * ldsrv: reads from the VFS-opened file MO via MO_READ into the
//!   memory-image MO it mapped via `trona_runtime::client::mm::*`.
//! * init: reads from the initrd bytes (the PE file is part of the
//!   boot CPIO; init treats initrd VA as a borrowed read source and
//!   copies into the memory-image MO it mmap'd against its own
//!   `mmsrv_self_control_cap`).
//!
//! Output layout: the planner returns the maximum memory-image byte
//! size (`size_of_image` rounded up to the page) plus a list of
//! `(src_file_offset, dst_rva, bytes)` copy commands that, when
//! executed in order, produce the canonical memory-image view of the
//! PE. The remainder of the memory-image MO is left zero, matching
//! how PE images lay out at runtime.

use super::header::{PeError, validate};

/// A single copy operation the caller must execute: read `bytes` from
/// `src_file_offset` of the source PE file and write them at `dst_rva`
/// inside the destination memory-image MO. `dst_rva` is the in-memory
/// offset the loader expects; `src_file_offset` is the raw file
/// position (NOT an RVA).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeCopy {
    pub src_file_offset: u64,
    pub dst_rva: u64,
    pub bytes: u64,
}

impl PeCopy {
    pub const EMPTY: PeCopy = PeCopy {
        src_file_offset: 0,
        dst_rva: 0,
        bytes: 0,
    };
}

/// Errors the planner can return. Each maps to `KERNITE_ERR_*` at the
/// caller boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeMemoryImageError {
    /// File slice shorter than the headers parse requires.
    TooSmall,
    /// `header::validate` rejected the leading DOS / PE / COFF / opt
    /// header bytes.
    BadHeaders,
    /// Sanity-check failure: empty image, `size_of_headers` oversize,
    /// entry RVA past image end, or a section oversize relative to
    /// the image.
    InvalidImage,
}

/// Bounded copy-list size. A typical PE has < 16 sections; this leaves
/// headroom for unusual section counts without forcing a heap
/// allocation in a `#![no_std]` context.
pub const MAX_COPIES: usize = 32;

/// Plan the copy list for a PE file at `file_bytes`. Writes up to
/// `MAX_COPIES` entries into `out_copies` and returns
/// `(image_size, size_of_headers, entry_rva, copies_len)`. The
/// caller treats `image_size` as the byte size of the memory-image MO
/// to allocate (round up to the page when actually creating the MO).
///
/// # Safety
/// `file_bytes` must be readable for `file_bytes.len()` bytes.
pub fn plan_memory_image(
    file_bytes: &[u8],
    out_copies: &mut [PeCopy; MAX_COPIES],
) -> Result<(u64, u64, u64, usize), PeMemoryImageError> {
    let headers =
        unsafe { validate(file_bytes.as_ptr(), file_bytes.len()) }.map_err(|e| match e {
            PeError::TooSmall => PeMemoryImageError::TooSmall,
            _ => PeMemoryImageError::BadHeaders,
        })?;
    let image_size = headers.opt.size_of_image as u64;
    let size_of_headers = headers.opt.size_of_headers as u64;
    let entry_rva = headers.opt.address_of_entry_point as u64;
    if image_size == 0
        || entry_rva >= image_size
        || size_of_headers == 0
        || size_of_headers > image_size
        || size_of_headers > file_bytes.len() as u64
    {
        return Err(PeMemoryImageError::InvalidImage);
    }

    let mut n = 0usize;

    // Header copy (RVA 0 → file offset 0). The DOS stub, PE signature,
    // COFF header, optional header, and data directories all live in
    // the first `size_of_headers` bytes.
    out_copies[n] = PeCopy {
        src_file_offset: 0,
        dst_rva: 0,
        bytes: size_of_headers,
    };
    n += 1;

    // Section copies (RVA → file offset from each section header).
    // Each section's file extent (`pointer_to_raw_data ..
    // pointer_to_raw_data + size_of_raw_data`) is copied to its RVA
    // window inside the memory-image MO; the section's
    // `virtual_size` can extend past `size_of_raw_data`, in which
    // case the trailing bytes are zero-filled by the anonymous MO.
    let sections = unsafe { headers.sections(file_bytes.as_ptr()) };
    for sec in sections.iter() {
        let raw = sec.size_of_raw_data as u64;
        if raw == 0 {
            continue;
        }
        let rva = sec.virtual_address as u64;
        let raw_off = sec.pointer_to_raw_data as u64;
        if rva >= image_size {
            return Err(PeMemoryImageError::InvalidImage);
        }
        let raw_end = match raw_off.checked_add(raw) {
            Some(end) => end,
            None => return Err(PeMemoryImageError::InvalidImage),
        };
        if raw_end > file_bytes.len() as u64 {
            return Err(PeMemoryImageError::InvalidImage);
        }
        let room = image_size - rva;
        if raw > room {
            return Err(PeMemoryImageError::InvalidImage);
        }
        if n >= out_copies.len() {
            return Err(PeMemoryImageError::InvalidImage);
        }
        out_copies[n] = PeCopy {
            src_file_offset: raw_off,
            dst_rva: rva,
            bytes: raw,
        };
        n += 1;
    }
    Ok((image_size, size_of_headers, entry_rva, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe_bytes() {
        let bogus = b"hello world, not a PE\0\0\0\0\0\0\0";
        let mut copies = [PeCopy::EMPTY; MAX_COPIES];
        assert!(plan_memory_image(bogus, &mut copies).is_err());
    }

    #[test]
    fn rejects_truncated_dos_header() {
        let mut copies = [PeCopy::EMPTY; MAX_COPIES];
        assert!(matches!(
            plan_memory_image(&[b'M', b'Z'], &mut copies),
            Err(PeMemoryImageError::TooSmall)
        ));
    }
}
