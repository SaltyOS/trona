//! kernel32.dll -- Rust-backed Win32 compatibility layer for PE programs.
//! SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![no_main]

extern crate uapi;

pub mod console;
pub mod crt;
pub mod error;
pub mod handle;
pub mod ipc;
pub mod paths;
pub mod pe_types;
pub mod process;
pub mod runtime;
pub mod syscall;
pub mod types;

pub use handle::HANDLE;
pub use trona_protocol::win32::*;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        syscall::yield_now();
    }
}
