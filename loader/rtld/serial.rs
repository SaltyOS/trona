//! SPDX-License-Identifier: GPL-2.0-only
//! RTLD diagnostic output via the runtime log sink.
//!
//! The runtime path uses an already-delivered `ROLE_LOG_CLIENT` and
//! falls back to `KernelDebug` for privileged bootstrap services.

use crate::rtld::syscall::rtld_syscall6;

/// Writes a single byte through the runtime diagnostic sink.
pub fn putchar(c: u8) {
    trona_runtime::debug::serial::serial_putc(c);
}

/// Writes a byte slice through the runtime diagnostic sink.
pub fn puts(s: &[u8]) {
    trona_runtime::debug::serial::serial_puts(s);
}

/// Writes a string literal to the serial console.
pub fn print(s: &str) {
    puts(s.as_bytes());
}

/// Writes a u64 value in hexadecimal to the serial console.
pub fn print_hex(val: u64) {
    puts(b"0x");
    if val == 0 {
        putchar(b'0');
        return;
    }
    // Find the highest non-zero nibble
    let mut started = false;
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xf) as u8;
        if nibble != 0 {
            started = true;
        }
        if started {
            let c = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
            putchar(c);
        }
    }
}

/// Writes a decimal u64 value to the serial console.
pub fn print_dec(val: u64) {
    if val == 0 {
        putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    let mut v = val;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        putchar(buf[i]);
    }
}

fn trona_error_name(err: u64) -> &'static str {
    match err {
        x if x == uapi::KERNITE_OK as u64 => "KERNITE_OK",
        x if x == uapi::KERNITE_ERR_INVALID_CAPABILITY as u64 => "KERNITE_ERR_INVALID_CAPABILITY",
        x if x == uapi::KERNITE_ERR_INVALID_OPERATION as u64 => "KERNITE_ERR_INVALID_OPERATION",
        x if x == uapi::KERNITE_ERR_INSUFFICIENT_RIGHTS as u64 => "KERNITE_ERR_INSUFFICIENT_RIGHTS",
        x if x == uapi::KERNITE_ERR_INVALID_ARGUMENT as u64 => "KERNITE_ERR_INVALID_ARGUMENT",
        x if x == uapi::KERNITE_ERR_OUT_OF_MEMORY as u64 => "KERNITE_ERR_OUT_OF_MEMORY",
        x if x == uapi::KERNITE_ERR_NOT_FOUND as u64 => "KERNITE_ERR_NOT_FOUND",
        x if x == uapi::KERNITE_ERR_BUSY as u64 => "KERNITE_ERR_BUSY",
        x if x == uapi::KERNITE_ERR_ALREADY_EXISTS as u64 => "KERNITE_ERR_ALREADY_EXISTS",
        x if x == uapi::KERNITE_ERR_WOULD_BLOCK as u64 => "KERNITE_ERR_WOULD_BLOCK",
        x if x == uapi::KERNITE_ERR_BAD_ADDRESS as u64 => "KERNITE_ERR_BAD_ADDRESS",
        x if x == uapi::KERNITE_ERR_OUT_OF_RANGE as u64 => "KERNITE_ERR_OUT_OF_RANGE",
        x if x == uapi::KERNITE_ERR_CANCELLED as u64 => "KERNITE_ERR_CANCELLED",
        x if x == uapi::KERNITE_ERR_RESTART as u64 => "KERNITE_ERR_RESTART",
        x if x == uapi::KERNITE_ERR_DEADLOCK as u64 => "KERNITE_ERR_DEADLOCK",
        x if x == uapi::KERNITE_ERR_INTERRUPTED as u64 => "KERNITE_ERR_INTERRUPTED",
        x if x == uapi::KERNITE_ERR_TOO_LARGE as u64 => "KERNITE_ERR_TOO_LARGE",
        x if x == uapi::KERNITE_ERR_NOT_SUPPORTED as u64 => "KERNITE_ERR_NOT_SUPPORTED",
        x if x == uapi::KERNITE_ERR_READONLY as u64 => "KERNITE_ERR_READONLY",
        x if x == uapi::KERNITE_ERR_SLOT_OCCUPIED as u64 => "KERNITE_ERR_SLOT_OCCUPIED",
        x if x == uapi::KERNITE_ERR_ALREADY_MAPPED as u64 => "KERNITE_ERR_ALREADY_MAPPED",
        x if x == uapi::KERNITE_ERR_PEER_CLOSED as u64 => "KERNITE_ERR_PEER_CLOSED",
        x if x == uapi::KERNITE_ERR_QUEUE_OVERFLOW as u64 => "KERNITE_ERR_QUEUE_OVERFLOW",
        x if x == uapi::KERNITE_ERR_WATCH_CANCELLED as u64 => "KERNITE_ERR_WATCH_CANCELLED",
        x if x == uapi::KERNITE_ERR_ABI_MISMATCH as u64 => "KERNITE_ERR_ABI_MISMATCH",
        x if x == uapi::KERNITE_ERR_IO_ERROR as u64 => "KERNITE_ERR_IO_ERROR",
        x if x == uapi::KERNITE_ERR_TIMED_OUT as u64 => "KERNITE_ERR_TIMED_OUT",
        x if x == uapi::KERNITE_ERR_PENDING as u64 => "KERNITE_ERR_PENDING",
        x if x == uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as u64 => {
            "KERNITE_ERR_INSUFFICIENT_RESOURCES"
        }
        _ => "KERNITE_UNKNOWN",
    }
}

pub fn print_trona_error(err: u64) {
    print(trona_error_name(err));
    print(" (");
    print_hex(err);
    putchar(b')');
}

/// Prints a fatal error message and halts.
pub fn fatal(msg: &str) -> ! {
    print("[ldtrona] FATAL: ");
    print(msg);
    putchar(b'\n');

    loop {
        let _ = rtld_syscall6(
            uapi::KERNITE_SYS_INVOKE as u64,
            uapi::KERNITE_CAP_SELF_TCB as u64,
            uapi::KERNITE_INV_TCB_YIELD as u64,
            0,
            0,
            0,
            0,
        );
    }
}

/// Prints a fatal error message with the decoded Trona kernel error and halts.
pub fn fatal_trona(msg: &str, err: u64) -> ! {
    print("[ldtrona] FATAL: ");
    print(msg);
    print(": ");
    print_trona_error(err);
    putchar(b'\n');

    loop {
        let _ = rtld_syscall6(
            uapi::KERNITE_SYS_INVOKE as u64,
            uapi::KERNITE_CAP_SELF_TCB as u64,
            uapi::KERNITE_INV_TCB_YIELD as u64,
            0,
            0,
            0,
            0,
        );
    }
}
