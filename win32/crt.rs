// Win32 PE CRT entry helpers for the Rust-backed kernel32.dll.
// SPDX-License-Identifier: GPL-2.0-only

use crate::handle;

/// Initialize the Win32 CRT. Called early in PE process startup.
///
/// # Safety
/// Must be called exactly once, before any Win32 API calls.
pub unsafe fn win32_crt_init() {
    unsafe {
        // Initialize the handle table with standard I/O handles
        handle::init_handle_table();
    }
}

/// PE CRT entry point: initialize, call WinMain-style entry, then ExitProcess.
///
/// # Safety
/// Called by the PE rtld. `entry_point` must be the PE image's AddressOfEntryPoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _win32_crt_entry(entry_point: u64) -> ! {
    unsafe {
        win32_crt_init();

        // Call the PE entry point (assumed to be: int entry(void))
        let entry_fn: extern "C" fn() -> i32 = core::mem::transmute(entry_point);
        let exit_code = entry_fn();

        crate::process::ExitProcess(exit_code as u32);
    }
}
