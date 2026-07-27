//! SPDX-License-Identifier: GPL-2.0-only
//! x86_64 ELF relocation type constants

pub const R_NONE: u32 = 0;
pub const R_ABS64: u32 = 1;
pub const R_GLOB_DAT: u32 = 6;
pub const R_JUMP_SLOT: u32 = 7;
pub const R_RELATIVE: u32 = 8;
pub const R_DTPMOD64: u32 = 16;
pub const R_DTPOFF64: u32 = 17;
pub const R_TPOFF64: u32 = 18;
pub const R_TLSDESC: u32 = 36;
pub const R_IRELATIVE: u32 = 37;
