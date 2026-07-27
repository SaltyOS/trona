//! SPDX-License-Identifier: GPL-2.0-only
//! AArch64 ELF relocation type constants

pub const R_NONE: u32 = 0;
pub const R_ABS64: u32 = 257;
pub const R_GLOB_DAT: u32 = 1025;
pub const R_JUMP_SLOT: u32 = 1026;
pub const R_RELATIVE: u32 = 1027;
pub const R_DTPMOD64: u32 = 1028;
pub const R_DTPOFF64: u32 = 1029;
pub const R_TPOFF64: u32 = 1030;
pub const R_TLSDESC: u32 = 1031;
pub const R_IRELATIVE: u32 = 1032;
