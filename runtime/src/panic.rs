// SPDX-License-Identifier: GPL-2.0-only
//
//! `#[panic_handler]` — formats the panic info on the serial console
//! and parks the thread via `syscall::yield_now()` so the kernel
//! can re-schedule onto something that's still alive.

use crate::debug::serial::LineBuf;
use crate::{SerialFmtWriter, panic_getpid};
use core::fmt::Write;
use trona_kernel::syscall;

#[panic_handler]
fn panic(info: &::core::panic::PanicInfo) -> ! {
    let mut line = LineBuf::new();
    line.str(b"[PANIC] userspace");

    if let Some(pid) = panic_getpid() {
        line.str(b" pid=");
        line.dec(pid);
    }

    if let Some(location) = info.location() {
        line.str(b" at ");
        line.str(location.file().as_bytes());
        line.putc(b':');
        line.dec(location.line() as u64);
        line.putc(b':');
        line.dec(location.column() as u64);
    }

    {
        let mut writer = SerialFmtWriter { line: &mut line };
        let _ = write!(&mut writer, ": {}", info.message());
    }

    line.putc(b'\n');
    line.flush();
    loop {
        syscall::yield_now();
    }
}
