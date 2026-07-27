//! SPDX-License-Identifier: GPL-2.0-only
//! RTLD-private raw syscall shim.

unsafe extern "C" {
    fn rtld_syscall6_raw(
        out: *mut u64,
        num: u64,
        a0: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    );
}

#[inline(always)]
pub fn rtld_syscall6(num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> (u64, u64) {
    let mut out = [0u64; 2];
    // SAFETY: `out` is a valid two-word result buffer for the rtld syscall helper.
    unsafe {
        rtld_syscall6_raw(out.as_mut_ptr(), num, a0, a1, a2, a3, a4, a5);
    }
    (out[0], out[1])
}
