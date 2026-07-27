//! Userland diagnostic output.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Non-privileged services write through `logsrv` when init delivered
//! `ROLE_LOG_CLIENT`. The log path never performs service discovery:
//! the endpoint must already be in the cap table. Privileged bootstrap
//! paths use the `KernelDebug` cap instead. This keeps kernel-debug
//! authority out of normal service CSpaces while preserving early boot
//! diagnostics.
//!
//! The [`LineBuf`] struct accumulates multiple fragments (strings, hex
//! numbers, decimals) into a single buffer and flushes atomically.

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc;
use trona_kernel::syscall::invoke;
use trona_protocol::log::{LOG_INLINE_BYTES, LOG_WRITE};

#[inline(always)]
fn kdebug_cap() -> u64 {
    crate::client::caps::kernel_debug_cap().addr()
}

fn log_cap() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const crate::__trona_cap_log_ep) }
}

struct LogWriteResult {
    written: usize,
}

fn log_write_to(ep: u64, s: &[u8]) -> LogWriteResult {
    if ep == 0 {
        return LogWriteResult { written: 0 };
    }
    let ctx = crate::current_ipc_ctx();
    if ctx.is_null() {
        return LogWriteResult { written: 0 };
    }

    let mut off = 0usize;
    while off < s.len() {
        let chunk = (s.len() - off).min(LOG_INLINE_BYTES);
        let words = (chunk + 7) / 8;
        let mut msg = TronaMsg::zeroed();
        msg.label = LOG_WRITE;
        msg.length = (1 + words) as u64;
        msg.regs[0] = chunk as u64;
        unsafe {
            let dst = &raw mut msg.regs[1] as *mut u8;
            for i in 0..chunk {
                *dst.add(i) = s[off + i];
            }
        }
        let err = unsafe { ipc::mp_write_ctx(ctx, ep, &raw const msg) };
        if err != 0 {
            return LogWriteResult { written: off };
        }
        off += chunk;
    }
    LogWriteResult { written: off }
}

/// Write a single byte to the userland log sink, falling back to
/// `KernelDebug` when no log service is available.
#[inline(always)]
pub fn serial_putc(c: u8) {
    let logged = log_write_to(log_cap(), &[c]);
    if logged.written == 1 {
        return;
    }
    let cap = kdebug_cap();
    if cap != 0 {
        invoke(
            cap,
            uapi::KERNITE_INV_KDEBUG_PUTCHAR as u64,
            c as u64,
            0,
            0,
            0,
        );
        return;
    }
}

/// Write a byte slice to the userland log sink, falling back to
/// `KernelDebug` for bootstrap and privileged-only paths.
pub fn serial_puts(s: &[u8]) {
    let logged = log_write_to(log_cap(), s);
    if logged.written == s.len() {
        return;
    }

    let cap = kdebug_cap();
    if cap != 0 {
        let mut off = logged.written;
        while off < s.len() {
            let chunk = if s.len() - off < 256 {
                s.len() - off
            } else {
                256
            };
            invoke(
                cap,
                uapi::KERNITE_INV_KDEBUG_PUTBUF as u64,
                s[off..].as_ptr() as u64,
                chunk as u64,
                0,
                0,
            );
            off += chunk;
        }
        return;
    }
}

/// Write a hexadecimal number to serial atomically (single syscall).
pub fn serial_hex(val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18]; // "0x" + up to 16 hex digits
    buf[0] = b'0';
    buf[1] = b'x';
    if val == 0 {
        buf[2] = b'0';
        serial_puts(&buf[..3]);
        return;
    }
    let mut tmp = [0u8; 16];
    let mut pos: usize = 16;
    let mut v = val;
    while v > 0 {
        pos -= 1;
        tmp[pos] = HEX[(v & 0xF) as usize];
        v >>= 4;
    }
    let digits = &tmp[pos..];
    let len = 2 + digits.len();
    buf[2..len].copy_from_slice(digits);
    serial_puts(&buf[..len]);
}

/// Write a decimal number to serial atomically (single syscall).
pub fn serial_dec(val: u64) {
    if val == 0 {
        serial_puts(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos: usize = 20;
    let mut v = val;
    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    serial_puts(&buf[pos..]);
}

/// Line buffer for compound serial output.
///
/// Accumulates multiple `.str()` / `.hex()` / `.dec()` calls into a single
/// buffer, then flushes atomically via one `serial_puts()` call. This ensures
/// compound messages (e.g. label + hex value + newline) are never interleaved
/// with output from other threads or CPUs.
///
/// ```rust
/// let mut lb = LineBuf::new();
/// lb.str(b"[TAG] Value=");
/// lb.hex(0x1234);
/// lb.str(b"\n");
/// lb.flush();
/// ```
pub struct LineBuf {
    buf: [u8; 256],
    pos: usize,
}

impl LineBuf {
    /// Create a new empty line buffer.
    pub fn new() -> Self {
        Self {
            buf: [0; 256],
            pos: 0,
        }
    }

    /// Append a byte slice to the buffer.
    pub fn str(&mut self, s: &[u8]) {
        for &b in s {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = b;
                self.pos += 1;
            }
        }
    }

    /// Append a byte slice (alias for `str`).
    pub fn bytes(&mut self, s: &[u8]) {
        self.str(s);
    }

    /// Append a hexadecimal number (with "0x" prefix) to the buffer.
    pub fn hex(&mut self, val: u64) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.str(b"0x");
        if val == 0 {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = b'0';
                self.pos += 1;
            }
            return;
        }
        let mut tmp = [0u8; 16];
        let mut p: usize = 16;
        let mut v = val;
        while v > 0 && p > 0 {
            p -= 1;
            tmp[p] = HEX[(v & 0xF) as usize];
            v >>= 4;
        }
        for i in p..16 {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = tmp[i];
                self.pos += 1;
            }
        }
    }

    /// Append a decimal number to the buffer.
    pub fn dec(&mut self, val: u64) {
        if val == 0 {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = b'0';
                self.pos += 1;
            }
            return;
        }
        let mut tmp = [0u8; 20];
        let mut p: usize = 20;
        let mut v = val;
        while v > 0 && p > 0 {
            p -= 1;
            tmp[p] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        for i in p..20 {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = tmp[i];
                self.pos += 1;
            }
        }
    }

    /// Append a single byte to the buffer.
    pub fn putc(&mut self, c: u8) {
        if self.pos < self.buf.len() - 1 {
            self.buf[self.pos] = c;
            self.pos += 1;
        }
    }

    /// Flush the buffer to serial output atomically, then reset.
    pub fn flush(&mut self) {
        if self.pos > 0 {
            serial_puts(&self.buf[..self.pos]);
            self.pos = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Compile-time-gated userland log macros
// ---------------------------------------------------------------------------

/// Debug-level log. Compiled out unless `ulog_debug` cfg is set.
///
/// The body receives `_lb: &mut LineBuf`, already initialized.
/// The buffer is flushed automatically when the block exits.
///
/// ```rust
/// udebug!({
///     _lb.str(b"[INIT] fork PID=");
///     _lb.hex(pid as u64);
///     _lb.str(b"\n");
/// });
/// ```
#[macro_export]
macro_rules! udebug {
    (|$lb:ident| { $($body:tt)* }) => {
        #[cfg(ulog_debug)]
        {
            let mut $lb = $crate::debug::serial::LineBuf::new();
            $($body)*
            $lb.flush();
        }
        #[cfg(not(ulog_debug))]
        {
            let _ = || {
                let mut $lb = $crate::debug::serial::LineBuf::new();
                $($body)*
            };
        }
    };
}

/// Info-level log. Compiled out unless `ulog_info` cfg is set (default at `info` level).
///
/// Same usage as `udebug!`.
#[macro_export]
macro_rules! uinfo {
    (|$lb:ident| { $($body:tt)* }) => {
        #[cfg(ulog_info)]
        {
            let mut $lb = $crate::debug::serial::LineBuf::new();
            $($body)*
            $lb.flush();
        }
        #[cfg(not(ulog_info))]
        {
            let _ = || {
                let mut $lb = $crate::debug::serial::LineBuf::new();
                $($body)*
            };
        }
    };
}

/// Warning-level log. Compiled out unless `ulog_warn` cfg is set.
///
/// Same usage as `udebug!`.
#[macro_export]
macro_rules! uwarn {
    (|$lb:ident| { $($body:tt)* }) => {
        #[cfg(ulog_warn)]
        {
            let mut $lb = $crate::debug::serial::LineBuf::new();
            $($body)*
            $lb.flush();
        }
        #[cfg(not(ulog_warn))]
        {
            let _ = || {
                let mut $lb = $crate::debug::serial::LineBuf::new();
                $($body)*
            };
        }
    };
}

/// Error-level log. Always unconditional — errors must never be silenced.
///
/// Same usage as `udebug!`.
#[macro_export]
macro_rules! uerror {
    (|$lb:ident| { $($body:tt)* }) => {
        {
            let mut $lb = $crate::debug::serial::LineBuf::new();
            $($body)*
            $lb.flush();
        }
    };
}
