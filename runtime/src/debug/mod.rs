// SPDX-License-Identifier: GPL-2.0-only
//
//! Early-boot debug surfaces — serial console, framebuffer reader.
//! Available before lazy lookup so panics during process bootstrap
//! still reach a console.

pub mod framebuffer;
pub mod serial;
