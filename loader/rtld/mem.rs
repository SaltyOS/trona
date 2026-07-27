//! SPDX-License-Identifier: GPL-2.0-only
//! RTLD memory helpers (page-granularity mapping, zero-fill)

use crate::common::elf::types::{PAGE_SIZE, page_align_up};

/// Zeros a memory region.
///
/// # Safety
/// `ptr` must point to `len` writable bytes.
pub unsafe fn memzero(ptr: *mut u8, len: usize) {
    let mut p = ptr;
    let end = unsafe { ptr.add(len) };
    while p < end {
        unsafe { p.write(0) };
        p = unsafe { p.add(1) };
    }
}

/// Copies `len` bytes from `src` to `dst`.
///
/// # Safety
/// Both ranges must be valid and non-overlapping (or dst < src).
pub unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0;
    while i < len {
        unsafe { *dst.add(i) = *src.add(i) };
        i += 1;
    }
}

/// Returns the number of pages needed for `size` bytes.
#[inline]
pub const fn pages_for(size: usize) -> usize {
    page_align_up(size) / PAGE_SIZE
}
