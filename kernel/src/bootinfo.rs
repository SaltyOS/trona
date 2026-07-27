//! Userland-side reader for the kernel boot info page mapped at
//! `KERNITE_BOOTINFO_VADDR`. Walks the TLV stream emitted by the
//! kernel (see `kernite/include/uapi/boot.h`).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use uapi::{
    KERNITE_BOOTINFO_MAGIC, KERNITE_BOOTINFO_TAG_END, KERNITE_BOOTINFO_VADDR, kernite_bootinfo_tlv,
};

const PAGE_BYTES: usize = 4096;

/// View into a single TLV record. `payload` covers exactly the
/// record's payload bytes (excludes the TLV header and trailing
/// alignment padding).
#[derive(Clone, Copy)]
pub struct TlvRecord {
    pub tag: u16,
    pub payload: *const u8,
    pub payload_len: usize,
}

impl TlvRecord {
    /// Borrow the payload as a slice. Lifetime is tied to the
    /// init's bootinfo mapping, which is stable for the life of PID1 —
    /// `'static` is therefore sound for callers that own that mapping.
    ///
    /// # Safety
    /// The mapping at `KERNITE_BOOTINFO_VADDR` must still be valid.
    pub unsafe fn payload_bytes(&self) -> &'static [u8] {
        unsafe { core::slice::from_raw_parts(self.payload, self.payload_len) }
    }
}

/// Bootinfo iterator. Walks tag/payload records until `TAG_END` or
/// the end of the page is reached.
pub struct BootinfoIter {
    cursor: *const u8,
    end: *const u8,
}

/// Try to construct a walker. Returns `None` if the page magic does
/// not match — the caller should treat that as "bootinfo
/// unavailable" and fall back accordingly.
///
/// # Safety
/// `KERNITE_BOOTINFO_VADDR` must be mapped read-only in the calling
/// process. The kernel maps it for PID1 bootstrap; normal services
/// must use their `AT_SALTYOS_STARTUP` metadata instead.
pub unsafe fn iter() -> Option<BootinfoIter> {
    let page = KERNITE_BOOTINFO_VADDR as *const u8;
    let magic = unsafe { core::ptr::read_volatile(page as *const u64) };
    if magic != KERNITE_BOOTINFO_MAGIC {
        return None;
    }
    let cursor = unsafe { page.add(8) };
    let end = unsafe { page.add(PAGE_BYTES) };
    Some(BootinfoIter { cursor, end })
}

impl Iterator for BootinfoIter {
    type Item = TlvRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let hdr_size = core::mem::size_of::<kernite_bootinfo_tlv>();
        if unsafe { self.cursor.add(hdr_size) } > self.end {
            return None;
        }
        let hdr_ptr = self.cursor as *const kernite_bootinfo_tlv;
        let hdr = unsafe { core::ptr::read_unaligned(hdr_ptr) };
        if hdr.tag == KERNITE_BOOTINFO_TAG_END as u16 {
            return None;
        }
        let payload_len = hdr.length as usize;
        let total = (hdr_size + payload_len + 7) & !7;
        if unsafe { self.cursor.add(total) } > self.end {
            return None;
        }
        let payload = unsafe { self.cursor.add(hdr_size) };
        self.cursor = unsafe { self.cursor.add(total) };
        Some(TlvRecord {
            tag: hdr.tag,
            payload,
            payload_len,
        })
    }
}

/// Find the first TLV record matching `tag` and return it.
///
/// # Safety
/// See [`iter`].
pub unsafe fn find_tlv(tag: u16) -> Option<TlvRecord> {
    unsafe { iter()?.find(|r| r.tag == tag) }
}

/// Read a fixed-size payload from a record. Returns `None` if the
/// record is missing or its payload is shorter than `T`. The payload
/// is read with `read_unaligned` so the bootinfo writer is free to
/// pack records without honoring `T`'s alignment.
///
/// # Safety
/// `T` must be a `#[repr(C)]` POD type that mirrors the on-wire
/// payload exactly. See [`iter`].
pub unsafe fn read_typed<T: Copy>(tag: u16) -> Option<T> {
    let record = unsafe { find_tlv(tag)? };
    if record.payload_len < core::mem::size_of::<T>() {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(record.payload as *const T) })
}
