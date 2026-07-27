//! SPDX-License-Identifier: GPL-2.0-only
//! ELF .dynamic section parsing and DT_NEEDED iteration

use super::types::*;

/// Parsed .dynamic section entries relevant to loading.
#[derive(Clone, Copy, Default)]
pub struct DynInfo {
    pub strtab: u64,
    pub strsz: u64,
    pub symtab: u64,
    pub syment: u64,
    pub rela: u64,
    pub relasz: u64,
    pub relaent: u64,
    pub jmprel: u64,
    pub pltrelsz: u64,
    pub pltgot: u64,
    pub pltrel: u64,
    pub init: u64,
    pub fini: u64,
    pub init_array: u64,
    pub init_arraysz: u64,
    pub fini_array: u64,
    pub fini_arraysz: u64,
    pub gnu_hash: u64,
    pub hash: u64,
    pub soname: u64,
    pub flags: u64,
    pub flags_1: u64,
    /// String table offset of the DT_RPATH entry (legacy).
    pub rpath: u64,
    /// String table offset of the DT_RUNPATH entry.
    pub runpath: u64,
    /// Address of DT_VERDEF table (or 0 if absent).
    pub verdef: u64,
    /// Number of entries in the DT_VERDEF table.
    pub verdef_num: u64,
    /// Address of DT_VERNEED table (or 0 if absent).
    pub verneed: u64,
    /// Number of entries in the DT_VERNEED table.
    pub verneed_num: u64,
    /// Address of DT_VERSYM table (or 0 if absent).
    pub versym: u64,
}

/// Parses a .dynamic section starting at `dyn_ptr`.
///
/// # Safety
/// `dyn_ptr` must point to a valid, null-terminated array of `Elf64Dyn`.
pub unsafe fn parse_dynamic(dyn_ptr: *const Elf64Dyn) -> DynInfo {
    let mut info = DynInfo::default();
    let mut p = dyn_ptr;

    loop {
        let entry = unsafe { &*p };
        match entry.d_tag {
            DT_NULL => break,
            DT_STRTAB => info.strtab = entry.d_val,
            DT_STRSZ => info.strsz = entry.d_val,
            DT_SYMTAB => info.symtab = entry.d_val,
            DT_SYMENT => info.syment = entry.d_val,
            DT_RELA => info.rela = entry.d_val,
            DT_RELASZ => info.relasz = entry.d_val,
            DT_RELAENT => info.relaent = entry.d_val,
            DT_JMPREL => info.jmprel = entry.d_val,
            DT_PLTRELSZ => info.pltrelsz = entry.d_val,
            DT_PLTGOT => info.pltgot = entry.d_val,
            DT_PLTREL => info.pltrel = entry.d_val,
            DT_INIT => info.init = entry.d_val,
            DT_FINI => info.fini = entry.d_val,
            DT_INIT_ARRAY => info.init_array = entry.d_val,
            DT_INIT_ARRAYSZ => info.init_arraysz = entry.d_val,
            DT_FINI_ARRAY => info.fini_array = entry.d_val,
            DT_FINI_ARRAYSZ => info.fini_arraysz = entry.d_val,
            DT_GNU_HASH => info.gnu_hash = entry.d_val,
            DT_HASH => info.hash = entry.d_val,
            DT_SONAME => info.soname = entry.d_val,
            DT_FLAGS => info.flags = entry.d_val,
            DT_FLAGS_1 => info.flags_1 = entry.d_val,
            DT_RPATH => info.rpath = entry.d_val,
            DT_RUNPATH => info.runpath = entry.d_val,
            DT_VERDEF => info.verdef = entry.d_val,
            DT_VERDEFNUM => info.verdef_num = entry.d_val,
            DT_VERNEED => info.verneed = entry.d_val,
            DT_VERNEEDNUM => info.verneed_num = entry.d_val,
            DT_VERSYM => info.versym = entry.d_val,
            _ => {}
        }
        p = unsafe { p.add(1) };
    }

    info
}

/// Iterator over DT_NEEDED entries. Yields string table offsets.
pub struct NeededIter {
    ptr: *const Elf64Dyn,
}

impl NeededIter {
    /// # Safety
    /// `dyn_ptr` must point to a valid, null-terminated `Elf64Dyn` array.
    pub unsafe fn new(dyn_ptr: *const Elf64Dyn) -> Self {
        Self { ptr: dyn_ptr }
    }
}

impl Iterator for NeededIter {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        loop {
            let entry = unsafe { &*self.ptr };
            if entry.d_tag == DT_NULL {
                return None;
            }
            self.ptr = unsafe { self.ptr.add(1) };
            if entry.d_tag == DT_NEEDED {
                return Some(entry.d_val);
            }
        }
    }
}

/// Resolves a string table offset to a byte slice.
///
/// # Safety
/// `strtab` must point to a valid string table of at least `strsz` bytes.
pub unsafe fn strtab_entry(strtab: *const u8, strsz: usize, offset: u64) -> Option<&'static [u8]> {
    let off = offset as usize;
    if off >= strsz {
        return None;
    }
    let start = unsafe { strtab.add(off) };
    let max_len = strsz - off;
    let mut len = 0;
    while len < max_len {
        if unsafe { *start.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    Some(unsafe { core::slice::from_raw_parts(start, len) })
}
