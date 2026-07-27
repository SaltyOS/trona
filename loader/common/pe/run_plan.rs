// SPDX-License-Identifier: GPL-2.0-only
//! PE → [`RunPlan`](crate::common::image) producer + post-map carve-list.
//!
//! The `ldsrv` code-loading authority relays a PE file into a **memory-image**
//! MemoryObject (sections copied from their file offsets to their RVAs, the
//! remainder zero-filled) before conferring `EXECUTE`. Because that MO is laid
//! out in memory order, a section's page offset in the MO equals its RVA, so the
//! producer classifies each page by section protection exactly like the ELF
//! producer: executable sections map shared `R-X`, read-only sections shared
//! `R--`, writable sections a private copy-on-write child `R-W`.
//!
//! [`build_carves`] enumerates the regions the PE loader writes *after* mapping
//! (the import address table, delay-import IAT + module handle, TLS index slot).
//! [`plan_pe`] forces those pages writable, so the post-map fixups land on `R-W`
//! pages and never require turning code writable — a carve that lands on an
//! executable page is rejected ([`PePlanError::WriteExecPage`]).

use super::header::PeHeaders;
use super::types::{
    DELAY_IMPORT_ATTR_RVA, DelayImportDescriptor, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, ImportDescriptor, SectionHeader, TlsDirectory64,
};
use crate::common::image::{
    Carve, ImageEnvelope, ImageRunKind, PROT_EXEC, PROT_READ, PROT_WRITE, Prot, Run, RunSource,
};

const PAGE: u64 = 4096;

/// Why a PE image cannot be reduced to a W^X-safe run plan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PePlanError {
    /// A page is both executable and writable — a W+X section, or a carve
    /// (post-map write target) that lands on executable code.
    WriteExecPage,
    /// The caller's run buffer was too small for the produced plan.
    TooManyRuns,
    /// The caller's carve buffer was too small for the produced plan.
    TooManyCarves,
    /// A PE metadata table referenced bytes outside the memory image.
    InvalidImage,
    /// Address arithmetic overflowed.
    Overflow,
}

#[inline]
fn page_align_up(v: u64) -> u64 {
    (v + PAGE - 1) & !(PAGE - 1)
}

#[inline]
fn page_align_down(v: u64) -> u64 {
    v & !(PAGE - 1)
}

/// Union the section protections covering page `rva`, then apply the carve
/// override (force writable). Pages outside every section (headers, padding)
/// are read-only. A page that ends up both executable and writable is rejected.
fn classify_pe_page(
    sections: &[SectionHeader],
    rva: u64,
    image_size: u64,
    carves: &[Carve],
) -> Result<u8, PePlanError> {
    let page_end = (rva + PAGE).min(image_size);
    let mut wants_exec = false;
    let mut wants_write = false;
    for sec in sections {
        let sec_rva = sec.virtual_address as u64;
        let sec_size = core::cmp::max(sec.virtual_size, sec.size_of_raw_data) as u64;
        if sec_size == 0 {
            continue;
        }
        let sec_end = sec_rva.saturating_add(sec_size);
        if sec_end <= rva || sec_rva >= page_end {
            continue;
        }
        if sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            wants_exec = true;
        }
        if sec.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            wants_write = true;
        }
    }
    let carved = carves.iter().any(|c| {
        let c_end = c.rva.saturating_add(c.bytes);
        c.rva < page_end && c_end > rva
    });
    if carved {
        wants_write = true;
    }
    if wants_exec && wants_write {
        return Err(PePlanError::WriteExecPage);
    }
    let mut prot = PROT_READ;
    if wants_exec {
        prot |= PROT_EXEC;
    }
    if wants_write {
        prot |= PROT_WRITE;
    }
    Ok(prot)
}

/// A maximal run of consecutive pages with the same protection.
struct PendingRun {
    start_va: u64,
    pages: u64,
    prot: u8,
}

impl PendingRun {
    fn end_va(&self) -> u64 {
        self.start_va + self.pages * PAGE
    }
}

fn emit(
    r: &PendingRun,
    load_base: u64,
    out: &mut [Run],
    count: &mut usize,
) -> Result<(), PePlanError> {
    if *count >= out.len() {
        return Err(PePlanError::TooManyRuns);
    }
    let bytes = r.pages.checked_mul(PAGE).ok_or(PePlanError::Overflow)?;
    let mo_offset_pages = r
        .start_va
        .checked_sub(load_base)
        .ok_or(PePlanError::Overflow)?
        / PAGE;
    let write = r.prot & PROT_WRITE != 0;
    let exec = r.prot & PROT_EXEC != 0;
    let (source, kind) = if write {
        // Writable runs (data, .bss, carves) are a private COW child of the
        // memory-image MO: it already holds the initialized bytes (or zeros for
        // BSS), so the whole run is "file" content — no tail to zero.
        (
            RunSource::PrivateFromCodeMo {
                mo_offset_pages,
                file_bytes: bytes,
            },
            ImageRunKind::Data,
        )
    } else if exec {
        (
            RunSource::CleanFromCodeMo { mo_offset_pages },
            ImageRunKind::Text,
        )
    } else {
        (
            RunSource::CleanFromCodeMo { mo_offset_pages },
            ImageRunKind::RoData,
        )
    };
    out[*count] = Run {
        va: r.start_va,
        bytes,
        prot: Prot(r.prot),
        kind,
        source,
    };
    *count += 1;
    Ok(())
}

/// Produce the run plan for a memory-image PE at `load_base`. `base` points at
/// the mapped (or header-region) PE image so the section table is readable;
/// `carves` are the post-map writable regions from [`build_carves`]. Returns the
/// envelope and the number of runs written to `out`.
pub fn plan_pe(
    pe: &PeHeaders,
    base: *const u8,
    load_base: u64,
    carves: &[Carve],
    out: &mut [Run],
) -> Result<(ImageEnvelope, usize), PePlanError> {
    let image_size = pe.opt.size_of_image as u64;
    let entry_pc = load_base.wrapping_add(pe.opt.address_of_entry_point as u64);
    let envelope = ImageEnvelope {
        base: load_base,
        bytes: page_align_up(image_size),
        load_base,
        entry_pc,
    };
    if image_size == 0 {
        return Ok((envelope, 0));
    }
    let sections = unsafe { pe.sections(base) };

    let mut count = 0usize;
    let mut run: Option<PendingRun> = None;
    let mut rva = 0u64;
    while rva < image_size {
        let prot = classify_pe_page(sections, rva, image_size, carves)?;
        let page_va = load_base.checked_add(rva).ok_or(PePlanError::Overflow)?;
        let extend = run
            .as_ref()
            .is_some_and(|r| r.prot == prot && r.end_va() == page_va);
        if extend {
            if let Some(r) = run.as_mut() {
                r.pages += 1;
            }
        } else {
            if let Some(r) = run.take() {
                emit(&r, load_base, out, &mut count)?;
            }
            run = Some(PendingRun {
                start_va: page_va,
                pages: 1,
                prot,
            });
        }
        rva = rva.checked_add(PAGE).ok_or(PePlanError::Overflow)?;
    }
    if let Some(r) = run.take() {
        emit(&r, load_base, out, &mut count)?;
    }
    Ok((envelope, count))
}

#[inline]
fn push_carve(
    out: &mut [Carve],
    n: &mut usize,
    image_size: u64,
    rva: u64,
    bytes: u64,
) -> Result<(), PePlanError> {
    if bytes == 0 {
        return Ok(());
    }
    let raw_end = rva.checked_add(bytes).ok_or(PePlanError::Overflow)?;
    if raw_end > image_size {
        return Err(PePlanError::InvalidImage);
    }
    if *n >= out.len() {
        return Err(PePlanError::TooManyCarves);
    }
    let start = page_align_down(rva);
    let end = page_align_up(raw_end);
    out[*n] = Carve {
        rva: start,
        bytes: end.checked_sub(start).ok_or(PePlanError::Overflow)?,
    };
    *n += 1;
    Ok(())
}

fn read_u64_at(read_at: &mut dyn FnMut(u64, &mut [u8]) -> bool, rva: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    if read_at(rva, &mut buf) {
        Some(u64::from_le_bytes(buf))
    } else {
        None
    }
}

#[inline]
fn range_within(inner_rva: u64, inner_bytes: u64, outer_rva: u64, outer_bytes: u64) -> bool {
    let Some(inner_end) = inner_rva.checked_add(inner_bytes) else {
        return false;
    };
    let Some(outer_end) = outer_rva.checked_add(outer_bytes) else {
        return false;
    };
    inner_rva >= outer_rva && inner_end <= outer_end
}

/// Enumerate the post-map writable regions of a PE image into `out`, returning
/// the carve count. `read_at(rva, buf)` reads `buf.len()` image bytes at `rva`
/// (the caller backs it with `MO_READ` over the memory-image code MO); it
/// returns `false` if the read fails, in which case the image is rejected.
///
/// Covered: each import descriptor's `FirstThunk` extent, the TLS index slot,
/// and each delay-import IAT + module-handle slot. The IAT data directory is
/// used only to cross-check import-descriptor `FirstThunk` ranges when present.
pub fn build_carves(
    pe: &PeHeaders,
    base: *const u8,
    read_at: &mut dyn FnMut(u64, &mut [u8]) -> bool,
    out: &mut [Carve],
) -> Result<usize, PePlanError> {
    let mut n = 0usize;
    let image_base = pe.opt.image_base;
    let image_size = pe.opt.size_of_image as u64;

    let iat_range = unsafe { pe.data_directory(base, IMAGE_DIRECTORY_ENTRY_IAT) }
        .map(|dd| (dd.virtual_address as u64, dd.size as u64));

    // 1. Import descriptors — carve each module's FirstThunk table. The combined
    //    IAT directory, when present, is only a consistency check; it is not used
    //    as the carve source because it can be stale or over-broad.
    if let Some(dd) = unsafe { pe.data_directory(base, IMAGE_DIRECTORY_ENTRY_IMPORT) } {
        let desc_size = core::mem::size_of::<ImportDescriptor>();
        let mut desc_rva = dd.virtual_address as u64;
        let end = desc_rva
            .checked_add(dd.size as u64)
            .ok_or(PePlanError::Overflow)?;
        loop {
            if desc_rva
                .checked_add(desc_size as u64)
                .ok_or(PePlanError::Overflow)?
                > end
            {
                break;
            }
            let mut buf = [0u8; core::mem::size_of::<ImportDescriptor>()];
            if !read_at(desc_rva, &mut buf) {
                return Err(PePlanError::InvalidImage);
            }
            // SAFETY: read_unaligned copies from a byte buffer holding a full
            // ImportDescriptor; no reference to unaligned storage is created.
            let desc =
                unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const ImportDescriptor) };
            if desc.name == 0 && desc.first_thunk == 0 {
                break;
            }
            if desc.first_thunk == 0 {
                return Err(PePlanError::InvalidImage);
            }
            let iat_rva = desc.first_thunk as u64;
            let mut thunks = 0u64;
            loop {
                let Some(value) = read_u64_at(read_at, iat_rva.saturating_add(thunks * 8)) else {
                    return Err(PePlanError::InvalidImage);
                };
                if value == 0 {
                    break;
                }
                thunks += 1;
                if thunks > 4096 {
                    return Err(PePlanError::InvalidImage);
                }
            }
            let bytes = (thunks + 1).checked_mul(8).ok_or(PePlanError::Overflow)?;
            if let Some((dir_rva, dir_bytes)) = iat_range {
                if !range_within(iat_rva, bytes, dir_rva, dir_bytes) {
                    return Err(PePlanError::InvalidImage);
                }
            }
            push_carve(out, &mut n, image_size, iat_rva, bytes)?;
            desc_rva = desc_rva
                .checked_add(desc_size as u64)
                .ok_or(PePlanError::Overflow)?;
        }
    }

    // 2. TLS index slot — `AddressOfIndex` is an absolute VA; carve the word it
    //    points at (the loader writes the module's TLS index there).
    if let Some(dd) = unsafe { pe.data_directory(base, IMAGE_DIRECTORY_ENTRY_TLS) } {
        let mut buf = [0u8; core::mem::size_of::<TlsDirectory64>()];
        if read_at(dd.virtual_address as u64, &mut buf) {
            // SAFETY: read_unaligned copies from a byte buffer holding a full
            // TlsDirectory64; no reference to unaligned storage is created.
            let tls = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const TlsDirectory64) };
            let aoi = tls.address_of_index;
            if aoi >= image_base {
                push_carve(out, &mut n, image_size, aoi - image_base, 8)?;
            }
        } else {
            return Err(PePlanError::InvalidImage);
        }
    }

    // 3. Delay imports — each descriptor's delay IAT and module-handle slot are
    //    written when the module is first delay-bound.
    if let Some(dd) = unsafe { pe.data_directory(base, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) } {
        let desc_size = core::mem::size_of::<DelayImportDescriptor>();
        let mut desc_rva = dd.virtual_address as u64;
        let end = desc_rva
            .checked_add(dd.size as u64)
            .ok_or(PePlanError::Overflow)?;
        loop {
            if desc_rva
                .checked_add(desc_size as u64)
                .ok_or(PePlanError::Overflow)?
                > end
            {
                break;
            }
            let mut buf = [0u8; core::mem::size_of::<DelayImportDescriptor>()];
            if !read_at(desc_rva, &mut buf) {
                return Err(PePlanError::InvalidImage);
            }
            // SAFETY: read_unaligned copies from a byte buffer holding a full
            // DelayImportDescriptor; no reference to unaligned storage is created.
            let desc =
                unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const DelayImportDescriptor) };
            if desc.attributes == 0 && desc.delay_import_address_table == 0 && desc.name == 0 {
                break; // zero terminator
            }
            // The RVA-attribute form stores RVAs; otherwise the fields are VAs.
            let to_rva = |v: u32| -> Option<u64> {
                if desc.attributes & DELAY_IMPORT_ATTR_RVA != 0 {
                    Some(v as u64)
                } else {
                    (v as u64).checked_sub(image_base)
                }
            };
            // Delay IAT size = count of thunks * 8; count by walking the delay
            // name table until a null entry.
            let diat = to_rva(desc.delay_import_address_table).ok_or(PePlanError::InvalidImage)?;
            let dint = to_rva(desc.delay_import_name_table).ok_or(PePlanError::InvalidImage)?;
            let mut thunks = 0u64;
            loop {
                let Some(value) = read_u64_at(read_at, dint.saturating_add(thunks * 8)) else {
                    return Err(PePlanError::InvalidImage);
                };
                if value == 0 {
                    break;
                }
                thunks += 1;
                if thunks > 4096 {
                    return Err(PePlanError::InvalidImage);
                }
            }
            let diat_bytes = (thunks + 1).checked_mul(8).ok_or(PePlanError::Overflow)?;
            push_carve(out, &mut n, image_size, diat, diat_bytes)?;
            if desc.module_handle != 0 {
                let module_handle = to_rva(desc.module_handle).ok_or(PePlanError::InvalidImage)?;
                push_carve(out, &mut n, image_size, module_handle, 8)?;
            }
            desc_rva = desc_rva
                .checked_add(desc_size as u64)
                .ok_or(PePlanError::Overflow)?;
        }
    }
    Ok(n)
}
