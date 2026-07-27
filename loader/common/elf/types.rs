//! SPDX-License-Identifier: GPL-2.0-only
//! ELF64 type definitions and constants

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Auxv {
    pub a_type: u64,
    pub a_val: u64,
}

/// GNU symbol-version definition record (DT_VERDEF entry).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Verdef {
    pub vd_version: u16,
    pub vd_flags: u16,
    pub vd_ndx: u16,
    pub vd_cnt: u16,
    pub vd_hash: u32,
    /// Byte offset from this entry to the first `Elf64Verdaux`.
    pub vd_aux: u32,
    /// Byte offset to the next `Elf64Verdef`. Zero terminates the chain.
    pub vd_next: u32,
}

/// Auxiliary record attached to an `Elf64Verdef`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Verdaux {
    /// String table offset of the version name.
    pub vda_name: u32,
    /// Byte offset to the next `Elf64Verdaux`. Zero terminates the chain.
    pub vda_next: u32,
}

/// GNU symbol-version requirement record (DT_VERNEED entry).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Verneed {
    pub vn_version: u16,
    pub vn_cnt: u16,
    /// String table offset of the providing file's SONAME.
    pub vn_file: u32,
    pub vn_aux: u32,
    pub vn_next: u32,
}

/// Auxiliary record attached to an `Elf64Verneed`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Vernaux {
    pub vna_hash: u32,
    pub vna_flags: u16,
    pub vna_other: u16,
    pub vna_name: u32,
    pub vna_next: u32,
}

pub const EI_MAG0: usize = 0;
pub const EI_MAG3: usize = 3;
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;

pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PT_GNU_STACK: u32 = 0x6474e551;
pub const PT_GNU_RELRO: u32 = 0x6474e552;

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_DEBUG: i64 = 21;
pub const DT_JMPREL: i64 = 23;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_FLAGS_1: i64 = 0x6ffffffb;
pub const DT_GNU_HASH: i64 = 0x6ffffef5;
pub const DT_VERSYM: i64 = 0x6ffffff0;
pub const DT_VERDEF: i64 = 0x6ffffffc;
pub const DT_VERDEFNUM: i64 = 0x6ffffffd;
pub const DT_VERNEED: i64 = 0x6ffffffe;
pub const DT_VERNEEDNUM: i64 = 0x6fffffff;

pub const DF_SYMBOLIC: u64 = 0x02;

pub const DF_1_NOW: u64 = 0x01;
pub const DF_1_GLOBAL: u64 = 0x02;
pub const DF_1_NODELETE: u64 = 0x08;
pub const DF_1_INITFIRST: u64 = 0x20;
pub const DF_1_NOOPEN: u64 = 0x40;
pub const DF_1_PIE: u64 = 0x08000000;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_TLS: u8 = 6;

pub const STV_DEFAULT: u8 = 0;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;

// ----- GNU symbol versioning -----
/// Version index reserved for symbols with strictly local visibility.
pub const VER_NDX_LOCAL: u16 = 0;
/// Version index reserved for the default/global (unversioned) version.
pub const VER_NDX_GLOBAL: u16 = 1;
/// `vd_flags` bit: this entry defines the file's base version.
pub const VER_FLG_BASE: u16 = 0x1;
/// `vd_flags` bit: weak version (do not bind without explicit request).
pub const VER_FLG_WEAK: u16 = 0x2;
/// `versym[i]` high bit: the symbol is hidden (never picked unless the
/// caller asks for this exact version).
pub const VERSYM_HIDDEN: u16 = 0x8000;
/// Mask isolating the version index in a `versym[i]` entry.
pub const VERSYM_VERSION: u16 = 0x7fff;

#[inline]
pub const fn elf64_st_bind(info: u8) -> u8 {
    info >> 4
}

#[inline]
pub const fn elf64_st_type(info: u8) -> u8 {
    info & 0xf
}

#[inline]
pub const fn elf64_st_visibility(other: u8) -> u8 {
    other & 0x3
}

#[inline]
pub const fn elf64_r_type(info: u64) -> u32 {
    info as u32
}

#[inline]
pub const fn elf64_r_sym(info: u64) -> u32 {
    (info >> 32) as u32
}

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_ENTRY: u64 = 9;
pub const AT_SALTYOS_STARTUP: u64 = 0x2005;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

#[inline]
pub const fn page_align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

#[inline]
pub const fn page_align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}
