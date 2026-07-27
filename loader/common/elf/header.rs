//! SPDX-License-Identifier: GPL-2.0-only
//! ELF header validation and program header parsing

use super::types::*;

#[derive(Clone, Copy, Debug)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    BadType,
    BadMachine,
    NoPhdr,
    PhdrOverflow,
}

/// Validates an ELF64 header at `base` with `len` bytes available.
///
/// # Safety
/// `base` must point to at least `len` readable bytes.
pub unsafe fn validate_ehdr(base: *const u8, len: usize) -> Result<&'static Elf64Ehdr, ElfError> {
    if len < core::mem::size_of::<Elf64Ehdr>() {
        return Err(ElfError::TooSmall);
    }
    let ehdr = unsafe { &*(base as *const Elf64Ehdr) };

    if ehdr.e_ident[EI_MAG0..=EI_MAG3] != ELFMAG {
        return Err(ElfError::BadMagic);
    }
    if ehdr.e_ident[EI_CLASS] != ELFCLASS64 {
        return Err(ElfError::Not64Bit);
    }
    if ehdr.e_ident[EI_DATA] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    if ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN {
        return Err(ElfError::BadType);
    }
    #[cfg(target_arch = "x86_64")]
    if ehdr.e_machine != EM_X86_64 {
        return Err(ElfError::BadMachine);
    }
    #[cfg(target_arch = "aarch64")]
    if ehdr.e_machine != EM_AARCH64 {
        return Err(ElfError::BadMachine);
    }

    Ok(ehdr)
}

/// Returns a slice of program headers from a validated ELF.
///
/// # Safety
/// `base` must point to a valid ELF file of at least `len` bytes.
pub unsafe fn phdr_slice(
    base: *const u8,
    len: usize,
    ehdr: &Elf64Ehdr,
) -> Result<&'static [Elf64Phdr], ElfError> {
    let phoff = ehdr.e_phoff as usize;
    let phnum = ehdr.e_phnum as usize;
    let phentsize = ehdr.e_phentsize as usize;

    if phnum == 0 {
        return Err(ElfError::NoPhdr);
    }
    let end = phoff
        .checked_add(phnum.checked_mul(phentsize).ok_or(ElfError::PhdrOverflow)?)
        .ok_or(ElfError::PhdrOverflow)?;
    if end > len {
        return Err(ElfError::PhdrOverflow);
    }

    Ok(unsafe { core::slice::from_raw_parts(base.add(phoff) as *const Elf64Phdr, phnum) })
}

/// Computes the virtual address span of all PT_LOAD segments.
/// Returns `(lo, hi)` where `lo` is the lowest vaddr (page-aligned down)
/// and `hi` is the highest vaddr+memsz (page-aligned up).
pub fn load_span(phdrs: &[Elf64Phdr]) -> Option<(u64, u64)> {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    let mut found = false;

    for ph in phdrs {
        if ph.p_type != PT_LOAD {
            continue;
        }
        found = true;
        let seg_lo = ph.p_vaddr;
        let seg_hi = ph.p_vaddr.checked_add(ph.p_memsz)?;
        if seg_lo < lo {
            lo = seg_lo;
        }
        if seg_hi > hi {
            hi = seg_hi;
        }
    }

    if !found {
        return None;
    }

    let lo = page_align_down(lo as usize) as u64;
    let hi = page_align_up(hi as usize) as u64;
    Some((lo, hi))
}

/// Returns `true` if this ELF has a PT_INTERP segment.
pub fn has_interp(phdrs: &[Elf64Phdr]) -> bool {
    phdrs.iter().any(|ph| ph.p_type == PT_INTERP)
}

/// Returns the interpreter path bytes from a PT_INTERP segment.
///
/// # Safety
/// `base` must point to a valid ELF file.
pub unsafe fn get_interp<'a>(base: *const u8, phdrs: &[Elf64Phdr]) -> Option<&'a [u8]> {
    for ph in phdrs {
        if ph.p_type != PT_INTERP {
            continue;
        }
        let start = unsafe { base.add(ph.p_offset as usize) };
        let mut len = ph.p_filesz as usize;
        // Strip trailing null if present
        if len > 0 {
            let slice = unsafe { core::slice::from_raw_parts(start, len) };
            if slice[len - 1] == 0 {
                len -= 1;
            }
        }
        return Some(unsafe { core::slice::from_raw_parts(start, len) });
    }
    None
}

/// Finds the PT_TLS program header if present.
pub fn find_tls_phdr(phdrs: &[Elf64Phdr]) -> Option<&Elf64Phdr> {
    phdrs.iter().find(|ph| ph.p_type == PT_TLS)
}

/// Finds the PT_DYNAMIC program header if present.
pub fn find_dynamic_phdr(phdrs: &[Elf64Phdr]) -> Option<&Elf64Phdr> {
    phdrs.iter().find(|ph| ph.p_type == PT_DYNAMIC)
}

/// Finds the PT_PHDR program header if present.
pub fn find_phdr_phdr(phdrs: &[Elf64Phdr]) -> Option<&Elf64Phdr> {
    phdrs.iter().find(|ph| ph.p_type == PT_PHDR)
}
