//! SPDX-License-Identifier: GPL-2.0-only
//! PE/COFF header validation and section parsing

use super::types::*;

/// PE validation errors.
#[derive(Clone, Copy, Debug)]
pub enum PeError {
    TooSmall,
    BadDosMagic,
    BadPeSignature,
    Not64Bit,
    BadMachine,
    SectionOverflow,
}

/// Validates the DOS + PE headers at `base`.
///
/// # Safety
/// `base` must point to at least `len` readable bytes.
pub unsafe fn validate(base: *const u8, len: usize) -> Result<PeHeaders, PeError> {
    if len < core::mem::size_of::<DosHeader>() {
        return Err(PeError::TooSmall);
    }

    let dos = unsafe { &*(base as *const DosHeader) };
    if dos.e_magic != DOS_MAGIC {
        return Err(PeError::BadDosMagic);
    }

    let pe_offset = dos.e_lfanew as usize;
    let coff_offset = pe_offset + 4; // skip PE signature
    let opt_offset = coff_offset + core::mem::size_of::<CoffHeader>();

    if opt_offset + core::mem::size_of::<OptionalHeader64>() > len {
        return Err(PeError::TooSmall);
    }

    let pe_sig = unsafe { *(base.add(pe_offset) as *const u32) };
    if pe_sig != PE_SIGNATURE {
        return Err(PeError::BadPeSignature);
    }

    let coff = unsafe { &*(base.add(coff_offset) as *const CoffHeader) };

    #[cfg(target_arch = "x86_64")]
    if coff.machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(PeError::BadMachine);
    }
    #[cfg(target_arch = "aarch64")]
    if coff.machine != IMAGE_FILE_MACHINE_ARM64 {
        return Err(PeError::BadMachine);
    }

    let opt = unsafe { &*(base.add(opt_offset) as *const OptionalHeader64) };
    if opt.magic != PE32_PLUS_MAGIC {
        return Err(PeError::Not64Bit);
    }

    let datadir_offset = opt_offset + core::mem::size_of::<OptionalHeader64>();
    let num_dirs = opt.number_of_rva_and_sizes as usize;
    let section_offset = datadir_offset + num_dirs * core::mem::size_of::<DataDirectory>();
    let num_sections = coff.number_of_sections as usize;

    let sections_end = section_offset + num_sections * core::mem::size_of::<SectionHeader>();
    if sections_end > len {
        return Err(PeError::SectionOverflow);
    }

    Ok(PeHeaders {
        dos,
        coff,
        opt,
        datadir_offset,
        num_dirs,
        section_offset,
        num_sections,
    })
}

/// Parsed PE header pointers.
pub struct PeHeaders {
    pub dos: &'static DosHeader,
    pub coff: &'static CoffHeader,
    pub opt: &'static OptionalHeader64,
    pub datadir_offset: usize,
    pub num_dirs: usize,
    pub section_offset: usize,
    pub num_sections: usize,
}

impl PeHeaders {
    /// Returns a data directory entry by index, if it exists.
    ///
    /// # Safety
    /// The PE base must still be mapped.
    pub unsafe fn data_directory(
        &self,
        base: *const u8,
        idx: usize,
    ) -> Option<&'static DataDirectory> {
        if idx >= self.num_dirs {
            return None;
        }
        let dd = unsafe {
            &*(base.add(self.datadir_offset + idx * core::mem::size_of::<DataDirectory>())
                as *const DataDirectory)
        };
        if dd.virtual_address == 0 || dd.size == 0 {
            return None;
        }
        Some(dd)
    }

    /// Returns the section headers as a slice.
    ///
    /// # Safety
    /// The PE base must still be mapped.
    pub unsafe fn sections(&self, base: *const u8) -> &'static [SectionHeader] {
        unsafe {
            core::slice::from_raw_parts(
                base.add(self.section_offset) as *const SectionHeader,
                self.num_sections,
            )
        }
    }
}
