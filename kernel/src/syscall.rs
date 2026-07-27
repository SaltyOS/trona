// SPDX-License-Identifier: GPL-2.0-only
//
//! Raw kernite syscall wrapper + capability-invocation entry.
//!
//! kernite exposes a single trap, `KERNITE_SYS_INVOKE`. Every kernel
//! operation reaches the kernel through capability invocation — the
//! cap_ptr in arg0 selects the target object and the (cap.obj_type,
//! label) pair in arg1 selects the operation. Other arguments carry
//! op-specific payload.
//!
//! # x86_64 Register ABI
//!
//! | Register | Direction | Purpose |
//! |----------|-----------|---------|
//! | `rax` | in/out | Syscall number in (always `KERNITE_SYS_INVOKE`), error code out |
//! | `rdi` | in | Argument 0 (cap_ptr) |
//! | `rsi` | in | Argument 1 (invoke label) |
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
//! | `x8` | in | Syscall number (always `KERNITE_SYS_INVOKE`) |
//! | `x0` | in/out | Argument 0 (cap_ptr) in, error code out |
//! | `x1` | in/out | Argument 1 (invoke label) in, return value out |
//! | `x2` | in | Argument 2 |
//! | `x3` | in | Argument 3 |
//! | `x4` | in | Argument 4 |
//! | `x5` | in | Argument 5 |
//!
//! `options(nostack)` is used because the syscall instruction does
//! not touch the user stack — the kernel switches to its own
//! per-thread stack.

use crate::core_types::TronaResult;

unsafe extern "C" {
    fn trona_kernel_invoke_raw(
        out: *mut TronaResult,
        cap_ptr: u64,
        invoke_label: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    );
}

/// Raw kernite trap wrapper. Always invokes
/// `uapi::KERNITE_SYS_INVOKE` against `cap_ptr` with `invoke_label`,
/// passing up to four additional argument words.
#[inline(always)]
pub fn invoke(cap_ptr: u64, invoke_label: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> TronaResult {
    let mut result = TronaResult { error: 0, value: 0 };
    // SAFETY: `result` is a valid out buffer and the assembly helper preserves
    // the Rust C ABI while issuing the kernel trap.
    unsafe {
        trona_kernel_invoke_raw(&mut result, cap_ptr, invoke_label, a2, a3, a4, a5);
    }
    result
}

// ---------------------------------------------------------------------------
// Futex on `CAP_SELF_VSPACE`. Wait/wake addresses are user-space
// virtual addresses; the kernel hashes per-VSpace.
// ---------------------------------------------------------------------------

/// Block while `*addr == expected`. Returns `KERNITE_OK` on wake,
/// `KERNITE_ERR_WOULD_BLOCK` if the value changed before the wait
/// took effect.
#[inline]
pub fn futex_wait(addr: *const u32, expected: u32) -> u64 {
    invoke(
        uapi::KERNITE_CAP_SELF_VSPACE as u64,
        uapi::KERNITE_INV_VSPACE_FUTEX_WAIT as u64,
        addr as u64,
        expected as u64,
        0,
        0,
    )
    .error
}

/// Block while `*addr == expected`, with a nanosecond timeout.
/// Returns `KERNITE_OK` on wake, `KERNITE_ERR_WOULD_BLOCK` if the
/// value changed, `KERNITE_ERR_TIMED_OUT` once the deadline elapses.
#[inline]
pub fn futex_wait_timeout(addr: *const u32, expected: u32, timeout_ns: u64) -> u64 {
    invoke(
        uapi::KERNITE_CAP_SELF_VSPACE as u64,
        uapi::KERNITE_INV_VSPACE_FUTEX_WAIT as u64,
        addr as u64,
        expected as u64,
        timeout_ns,
        0,
    )
    .error
}

/// Wake up to `count` threads waiting on `addr`. Returns the number
/// actually woken in `value`.
#[inline]
pub fn futex_wake(addr: *const u32, count: u32) -> u64 {
    invoke(
        uapi::KERNITE_CAP_SELF_VSPACE as u64,
        uapi::KERNITE_INV_VSPACE_FUTEX_WAKE as u64,
        addr as u64,
        count as u64,
        0,
        0,
    )
    .value
}

/// Wake up to `wake_count` waiters on `addr`, then requeue up to
/// `requeue_count` of the still-blocked `addr` waiters onto `requeue_addr`
/// (`zx_futex_requeue` shape). `expected` guards the lost-wakeup race —
/// `*addr` must still equal it. Returns the number of threads woken.
#[inline]
pub fn futex_requeue(
    addr: *const u32,
    wake_count: u32,
    requeue_addr: *const u32,
    requeue_count: u32,
    expected: u32,
) -> u64 {
    invoke(
        uapi::KERNITE_CAP_SELF_VSPACE as u64,
        uapi::KERNITE_INV_VSPACE_FUTEX_REQUEUE as u64,
        addr as u64,
        requeue_addr as u64,
        ((wake_count as u64) << 32) | (requeue_count as u64),
        expected as u64,
    )
    .value
}

// ---------------------------------------------------------------------------
// TCB self-control on `CAP_SELF_TCB`.
// ---------------------------------------------------------------------------

/// Terminate the calling thread via the kernel's exit-self primitive,
/// which destroys whichever thread is currently running — correct even
/// for an auxiliary thread whose `CAP_SELF_TCB` slot names the process
/// main thread rather than itself. Does not return on success.
#[inline]
pub fn thread_exit() -> ! {
    let _ = invoke(
        uapi::KERNITE_CAP_SELF_TCB as u64,
        uapi::KERNITE_INV_TCB_EXIT_SELF as u64,
        0,
        0,
        0,
        0,
    );
    loop {
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// System capability invocations — the new system caps (KernelRng /
// SystemInfo / SystemControl / Clock / KernelDebug) are passed
// explicitly so substrate does not assume any well-known slot.
// Spawners place these caps at spawner-chosen child slots; lib code
// reads them via `caps::*` getters and threads them in.
// ---------------------------------------------------------------------------

/// Fill `dst[..len]` with bytes from a `KernelRng` cap. Returns a
/// `TronaResult` whose `value` is the number of bytes copied.
#[inline]
pub fn rng_read_bytes(rng_cap: u64, dst: *mut u8, len: usize) -> TronaResult {
    invoke(
        rng_cap,
        uapi::KERNITE_INV_RNG_READ as u64,
        dst as u64,
        len as u64,
        0,
        0,
    )
}

/// Snapshot global PMM accounting counters into `*out_uaddr` via a
/// `SystemInfo` cap. Returns 0 on success or a `KERNITE_ERR_*` code.
///
/// Raw form — caller passes a userland address as `u64`. Typed
/// wrapper lives in `trona_runtime::core::sysinfo_ext`. Long-term the
/// `TronaSysMemInfo` shape will be promoted to `uapi`.
#[inline]
pub fn system_get_meminfo_raw(sysinfo_cap: u64, out_uaddr: u64) -> u64 {
    invoke(
        sysinfo_cap,
        uapi::KERNITE_INV_SYSINFO_GET_MEMINFO as u64,
        out_uaddr,
        0,
        0,
        0,
    )
    .error
}

/// Typed form of [`system_get_meminfo_raw`]. The only pointer-to-word
/// conversion stays at the syscall boundary so callers do not spread
/// address casts through service code.
#[inline]
pub fn system_get_meminfo<T>(sysinfo_cap: u64, out: *mut T) -> u64 {
    system_get_meminfo_raw(sysinfo_cap, out as u64)
}

/// Snapshot system-wide CPU/time accounting through a `SystemInfo`
/// cap. Writes a `TronaSysInfo` header to `header_uaddr`, and up to
/// `capacity` `TronaSysInfoCpu` records to `cpu_array_uaddr` (pass 0
/// for header-only). Returns the raw `(error, cpus_written)`: `error`
/// is 0 on success or a `KERNITE_ERR_*` code; `value` is the per-CPU
/// record count actually copied.
///
/// Raw form — caller passes userland addresses as `u64`.
#[inline]
pub fn system_get_info_raw(
    sysinfo_cap: u64,
    header_uaddr: u64,
    cpu_array_uaddr: u64,
    capacity: u64,
) -> TronaResult {
    invoke(
        sysinfo_cap,
        uapi::KERNITE_INV_SYSINFO_GET_INFO as u64,
        header_uaddr,
        cpu_array_uaddr,
        capacity,
        0,
    )
}

/// Typed form of [`system_get_info_raw`]. `header` points at a
/// `TronaSysInfo`; `cpu_array` at the first of `capacity`
/// `TronaSysInfoCpu` records (or null for header-only). Returns
/// `(error, cpus_written)`.
#[inline]
pub fn system_get_info<H, C>(
    sysinfo_cap: u64,
    header: *mut H,
    cpu_array: *mut C,
    capacity: u64,
) -> TronaResult {
    system_get_info_raw(sysinfo_cap, header as u64, cpu_array as u64, capacity)
}

/// Trigger ACPI S5 power-off via a `SystemControl` cap. Does not
/// return on success.
#[inline]
pub fn system_shutdown(syscontrol_cap: u64) -> ! {
    invoke(
        syscontrol_cap,
        uapi::KERNITE_INV_SYSTEM_SHUTDOWN as u64,
        0,
        0,
        0,
        0,
    );
    loop {}
}

/// Read the kernel's monotonic clock through a `Clock` cap. Returns
/// nanoseconds since boot, or `0` if the invocation fails (caller's
/// preferred behaviour for hot paths that cannot fail meaningfully).
#[inline]
pub fn clock_read_monotonic(clock_cap: u64) -> u64 {
    let r = invoke(
        clock_cap,
        uapi::KERNITE_INV_CLOCK_READ as u64,
        uapi::KERNITE_CLOCK_ID_MONOTONIC as u64,
        0,
        0,
        0,
    );
    if r.error == 0 { r.value } else { 0 }
}

/// Read the kernel's realtime clock through a `Clock` cap. Returns
/// nanoseconds since the UNIX epoch, or `0` on error.
#[inline]
pub fn clock_read_realtime(clock_cap: u64) -> u64 {
    let r = invoke(
        clock_cap,
        uapi::KERNITE_INV_CLOCK_READ as u64,
        uapi::KERNITE_CLOCK_ID_REALTIME as u64,
        0,
        0,
        0,
    );
    if r.error == 0 { r.value } else { 0 }
}

/// Yield the current thread's quantum back to the scheduler via the
/// caller's own TCB cap. Equivalent to the old `SYS_YIELD` syscall,
/// folded into the single-syscall ABI as `TCB_YIELD` on `CAP_SELF_TCB`.
#[inline]
pub fn yield_now() {
    let _ = invoke(
        uapi::KERNITE_CAP_SELF_TCB as u64,
        uapi::KERNITE_INV_TCB_YIELD as u64,
        0,
        0,
        0,
        0,
    );
}
