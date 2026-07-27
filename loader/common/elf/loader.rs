//! SPDX-License-Identifier: GPL-2.0-only
//! ELF loader helpers — pure parsing (no syscall dependencies)

use super::header;

/// Phdr info for auxv construction.
pub struct PhdrInfo {
    pub phdr_vaddr: u64,
    pub phent: u16,
    pub phnum: u16,
}

/// Extracts PT_PHDR info needed for AT_PHDR/AT_PHENT/AT_PHNUM auxv entries.
///
/// # Safety
/// `data` must point to a valid ELF file of `len` bytes.
pub unsafe fn get_phdr_info(data: *const u8, len: usize, load_base: u64) -> Option<PhdrInfo> {
    unsafe {
        let ehdr = header::validate_ehdr(data, len).ok()?;
        let phdrs = header::phdr_slice(data, len, ehdr).ok()?;
        let (lo, _) = header::load_span(phdrs)?;
        let phdr_vaddr = match header::find_phdr_phdr(phdrs) {
            Some(pt_phdr) => pt_phdr.p_vaddr,
            None => ehdr.e_phoff,
        };
        Some(PhdrInfo {
            phdr_vaddr: load_base + phdr_vaddr - lo,
            phent: ehdr.e_phentsize,
            phnum: ehdr.e_phnum,
        })
    }
}
