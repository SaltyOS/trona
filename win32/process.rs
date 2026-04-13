// Win32 process API — ExitProcess, GetCurrentProcess.
// SPDX-License-Identifier: GPL-2.0-only

use crate::handle::*;
use crate::error::*;
use crate::trona;

use crate::trona::consts::kernel::*;
use crate::trona::protocol::procmgr::*;
use crate::trona::types::core::*;

/// Pseudo-handle for the current process (matches Windows convention).
const CURRENT_PROCESS_PSEUDO_HANDLE: HANDLE = -1;

/// Win32 ExitProcess — terminate the calling process.
///
/// Sends PM_EXIT to procmgr with blocking IPC so the thread does not resume
/// in userspace after teardown begins. Win32 client lifecycle is owned by
/// procmgr/VFS now, so csrss is no longer part of the exit fast path.
#[unsafe(no_mangle)]
pub extern "C" fn ExitProcess(u_exit_code: u32) -> ! {
    unsafe {
        // PM_EXIT intentionally never gets a reply. Blocking in Call keeps the
        // exiting thread parked in-kernel until procmgr suspends it.
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_EXIT;
        msg.regs[0] = u_exit_code as u64;
        msg.length = 1;
        let ctx = trona::current_ipc_ctx();
        let _ = trona::ipc::call_ctx(ctx, trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
    }

    // Should not return — procmgr kills us
    loop {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

/// Win32 GetCurrentProcess — return a pseudo-handle for the current process.
#[unsafe(no_mangle)]
pub extern "C" fn GetCurrentProcess() -> HANDLE {
    CURRENT_PROCESS_PSEUDO_HANDLE
}

/// Win32 GetCurrentProcessId — return the process ID.
#[unsafe(no_mangle)]
pub extern "C" fn GetCurrentProcessId() -> DWORD {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_GETPID;
        msg.length = 0;
        let ctx = trona::current_ipc_ctx();
        let err = trona::ipc::call_ctx(ctx, trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err == 0 && reply.label == TRONA_OK {
            reply.regs[0] as DWORD
        } else {
            0
        }
    }
}
