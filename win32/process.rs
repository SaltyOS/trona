// Win32 process API — ExitProcess, GetCurrentProcess.
// SPDX-License-Identifier: GPL-2.0-only

use crate::handle::*;
use crate::ipc;
use crate::runtime;
use crate::syscall;
use crate::types::TronaMsg;
use trona_protocol::common::TRONA_OK;
use trona_protocol::init::INIT_GET_PID;
use trona_protocol::win32::INIT_EXIT;

/// Pseudo-handle for the current process (matches Windows convention).
const CURRENT_PROCESS_PSEUDO_HANDLE: HANDLE = -1;

/// Win32 ExitProcess — terminate the calling process.
///
/// Sends `INIT_EXIT` as a blocking one-way message and then exits the
/// current thread. Init owns process teardown and does not reply to
/// this protocol record.
#[unsafe(no_mangle)]
pub extern "C" fn ExitProcess(u_exit_code: u32) -> ! {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        msg.label = INIT_EXIT;
        msg.regs[0] = u_exit_code as u64;
        msg.length = 1;
        let ctx = runtime::current_ipc_ctx();

        let _ = ipc::mp_write_ctx(ctx, runtime::caps::init_ep(), &raw const msg);
        syscall::thread_exit()
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
        msg.label = INIT_GET_PID;
        msg.length = 0;
        let ctx = runtime::current_ipc_ctx();
        let err = ipc::mp_call_ctx(
            ctx,
            runtime::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
            crate::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err == 0 && reply.label == TRONA_OK {
            reply.regs[0] as DWORD
        } else {
            0
        }
    }
}
