// Win32 PE CRT — C runtime initialization for PE binaries.
// SPDX-License-Identifier: GPL-2.0-only
//
// Called by the PE rtld after loading the PE image. Sets up:
// - IPC buffer
// - Slot allocator
// - Standard handles (stdin=0, stdout=1, stderr=2)
// - Calls the PE entry point
// - On return, calls ExitProcess
//
// The PE rtld passes the win32_csrss endpoint via AT_SALTYOS_WIN32SRV
// in the auxiliary vector. This is stored in __win32srv_ep for use
// by the console and process APIs.

use crate::handle;

/// Win32 subsystem server endpoint cap slot.
/// Set by the PE rtld from AT_SALTYOS_WIN32SRV. 0 = no server available.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __win32srv_ep: u64 = 0;

/// Initialize the Win32 CRT. Called early in PE process startup.
///
/// # Safety
/// Must be called exactly once, before any Win32 API calls.
pub unsafe fn win32_crt_init() {
    unsafe {
        // Initialize the handle table with standard I/O handles
        handle::init_handle_table();

        // Register with win32_csrss if available
        let ep = *(&raw const __win32srv_ep);
        if ep != 0 {
            let mut msg = trona::types::TronaMsg::zeroed();
            let mut reply = trona::types::TronaMsg::zeroed();
            msg.label = crate::W32_CLIENT_REGISTER;
            msg.length = 0;
            let ctx = trona::current_ipc_ctx();
            let _ = trona::ipc::call_ctx(ctx, ep, &raw const msg, &raw mut reply);
        }
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
