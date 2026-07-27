//! SPDX-License-Identifier: GPL-2.0-only
//! trona_loader — Unified ELF/PE loader and RTLD crate

#![no_std]

pub mod common;
#[cfg(rtld_binary)]
pub mod rtld;
