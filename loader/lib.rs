//! trona_loader -- ELF loading, CPIO parsing, and dynamic linking support
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! This crate provides the building blocks for process loading:
//!
//! - **`elf_loader`** -- ELF64 loader with scratch-map page-by-page strategy
//! - **`elf_dynamic`** -- Dynamic section parser and relocation support
//! - **`cpio`** -- CPIO archive iterator for initrd parsing

#![no_std]

extern crate trona;
extern crate trona_posix;

pub mod cpio;
pub mod elf_dynamic;
pub mod elf_loader;
