//! Raw system call interface
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Single inline-assembly wrapper for all SaltyOS kernel syscalls.
//!
//! # x86_64 Register ABI
//!
//! | Register | Direction | Purpose |
//! |----------|-----------|---------|
//! | `rax` | in/out | Syscall number in, error code out |
//! | `rdi` | in | Argument 0 (e.g. cap slot) |
//! | `rsi` | in | Argument 1 (e.g. msginfo) |
//! | `rdx` | in/out | Argument 2 in, return value out |
//! | `r10` | in | Argument 3 |
//! | `r8` | in | Argument 4 |
//! | `r9` | in | Argument 5 |
//! | `rcx` | clobbered | Kernel overwrites with return RIP |
//! | `r11` | clobbered | Kernel overwrites with saved RFLAGS |
//!
//! # AArch64 Register ABI
//!
//! | Register | Direction | Purpose |
//! |----------|-----------|---------|
//! | `x8` | in | Syscall number |
//! | `x0` | in/out | Argument 0 in, error code out |
//! | `x1` | in/out | Argument 1 in, return value out |
//! | `x2` | in | Argument 2 |
//! | `x3` | in | Argument 3 |
//! | `x4` | in | Argument 4 |
//! | `x5` | in | Argument 5 |
//!
//! `options(nostack)` is used because the syscall instruction does not
//! touch the user stack -- the kernel switches to its own per-thread stack.

use crate::types::TronaResult;

/// Issue a raw syscall with up to 6 arguments.
///
/// Returns a [`TronaResult`] with `error` (0 = success) and `value`
/// (syscall-specific return payload).
#[inline(always)]
pub fn syscall(num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> TronaResult {
    let error: u64;
    let value: u64;

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num => error,
            in("rdi") a0,
            in("rsi") a1,
            inlateout("rdx") a2 => value,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        // AArch64 syscall ABI: x8 = syscall number, x0-x5 = args
        // Returns: x0 = error, x1 = value
        core::arch::asm!(
            "svc #0",
            in("x8") num,
            inlateout("x0") a0 => error,
            inlateout("x1") a1 => value,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            options(nostack),
        );
    }

    TronaResult { error, value }
}

/// Futex wait: block if `*addr == expected`, return 0 on wake.
/// Returns TRONA_WOULD_BLOCK (9) if value changed.
#[inline]
pub fn futex_wait(addr: *const u32, expected: u32) -> u64 {
    syscall(
        crate::consts::SYS_FUTEX,
        addr as u64,
        crate::consts::FUTEX_WAIT,
        expected as u64,
        0,
        0,
        0,
    )
    .error
}

/// Futex wait with timeout: block if `*addr == expected`, wake after timeout_ns.
/// Returns 0 on successful wake, TRONA_WOULD_BLOCK (9) if value changed,
/// TRONA_CANCELLED (12) on timeout.
#[inline]
pub fn futex_wait_timeout(addr: *const u32, expected: u32, timeout_ns: u64) -> u64 {
    syscall(
        crate::consts::SYS_FUTEX,
        addr as u64,
        crate::consts::FUTEX_WAIT_TIMEOUT,
        expected as u64,
        timeout_ns,
        0,
        0,
    )
    .error
}

#[inline]
pub fn thread_exit() -> ! {
    let _ = syscall(crate::consts::SYS_THREAD_EXIT, 0, 0, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Futex wake: wake up to `count` threads waiting on `addr`.
/// Returns the number of threads actually woken.
#[inline]
pub fn futex_wake(addr: *const u32, count: u32) -> u64 {
    syscall(
        crate::consts::SYS_FUTEX,
        addr as u64,
        crate::consts::FUTEX_WAKE,
        count as u64,
        0,
        0,
        0,
    )
    .value
}

/// Get a 64-bit hardware random number from the kernel (RDRAND).
///
/// Returns `Some(value)` on success, `None` if the hardware RNG is unavailable.
#[inline]
pub fn sys_getrandom() -> Option<u64> {
    let r = syscall(crate::consts::SYS_GETRANDOM, 0, 0, 0, 0, 0, 0);
    if r.error == 0 {
        Some(r.value)
    } else {
        None
    }
}

/// Trigger ACPI S5 power-off shutdown.
///
/// This syscall does not return on success. The system is powered off.
#[inline]
pub fn sys_shutdown() -> ! {
    syscall(crate::consts::SYS_SHUTDOWN, 0, 0, 0, 0, 0, 0);
    // Should never reach here; the kernel halts
    loop {}
}

/// Send message to endpoint with timeout.
///
/// Returns 0 on success, `TRONA_CANCELLED` (12) on timeout.
/// Timeout is read from `IpcBuffer.timeout_ns` (must be set before calling).
#[inline]
pub fn sys_send_timed(cap: u64, msg_info: u64, mr0: u64, mr1: u64, mr2: u64, mr3: u64) -> u64 {
    syscall(
        crate::consts::SYS_SEND_TIMED,
        cap,
        msg_info,
        mr0,
        mr1,
        mr2,
        mr3,
    )
    .error
}

/// Receive message from endpoint with timeout.
///
/// Returns `TronaResult` where:
/// - `error == 0, value == badge` on success (message in IPC buffer)
/// - `error == TRONA_CANCELLED` on timeout
#[inline]
pub fn sys_recv_timed(cap: u64, timeout_ns: u64) -> TronaResult {
    syscall(crate::consts::SYS_RECV_TIMED, cap, timeout_ns, 0, 0, 0, 0)
}
