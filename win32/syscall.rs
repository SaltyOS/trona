// SPDX-License-Identifier: GPL-2.0-only
//
//! Raw kernite syscall wrappers for the PE-target kernel32.dll.
//!
//! kernite exposes a single trap (`KERNITE_SYS_INVOKE`); every kernel
//! operation is a capability invocation against `cap_ptr` with an
//! `invoke_label` plus four argument words. This file is the PE-side
//! mirror of substrate's `syscall::invoke` / `yield_now`.

use crate::types::TronaResult;

unsafe extern "C" {
    fn kernel32_invoke_raw(
        out: *mut TronaResult,
        cap_ptr: u64,
        invoke_label: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    );
}

/// Raw kernite trap — invokes `KERNITE_SYS_INVOKE` against `cap_ptr`
/// with the given `invoke_label` and four extra argument words.
#[inline(always)]
pub fn invoke(cap_ptr: u64, invoke_label: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> TronaResult {
    let mut result = TronaResult { error: 0, value: 0 };
    // SAFETY: `result` is a valid out buffer and the PE assembly helper adapts
    // the target C ABI to the SaltyOS syscall register ABI.
    unsafe {
        kernel32_invoke_raw(&mut result, cap_ptr, invoke_label, a2, a3, a4, a5);
    }
    result
}

/// Yield the current thread back to the scheduler via the caller's own
/// TCB (`KERNITE_CAP_SELF_TCB`).
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

/// Terminate the calling thread through its own TCB. This mirrors
/// substrate's `thread_exit` tail for PE code that cannot link
/// `trona_kernel` directly.
#[inline]
pub fn thread_exit() -> ! {
    let _ = invoke(
        uapi::KERNITE_CAP_SELF_TCB as u64,
        uapi::KERNITE_INV_TCB_KILL as u64,
        0,
        0,
        0,
        0,
    );
    loop {
        core::hint::spin_loop();
    }
}
