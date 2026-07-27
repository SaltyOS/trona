// SPDX-License-Identifier: GPL-2.0-only
//
//! Display server wire labels.

pub const DISPLAY_GET_INFO: u64 = 1;
pub const DISPLAY_PRESENT: u64 = 2;
pub const DISPLAY_FILL_RECT: u64 = 6;
pub const DISPLAY_WRITE_TEXT: u64 = 7;
pub const DISPLAY_TERMINAL_WRITE: u64 = 8;
pub const DISPLAY_SETUP_RING: u64 = 0xA10;
pub const DISPLAY_SETUP_CONSOLE_RING: u64 = 0xA11;
