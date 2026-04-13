//! kernel32.dll -- Rust-backed Win32 compatibility layer for PE programs.
//! SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![no_main]

pub mod console;
pub mod crt;
pub mod error;
pub mod handle;
pub mod paths;
pub mod process;
pub mod protocol;
pub mod trona;

pub use handle::HANDLE;
pub use protocol::*;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        let _ = trona::syscall::syscall(trona::consts::kernel::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
