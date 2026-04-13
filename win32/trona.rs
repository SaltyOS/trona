// Minimal trona compatibility shim for the Rust-backed PE kernel32.dll.
// SPDX-License-Identifier: GPL-2.0-only

pub mod consts {
    pub mod kernel {
        pub const TRONA_OK: u64 = 0;
        pub const TRONA_INVALID_CAPABILITY: u64 = 1;
        pub const TRONA_INVALID_OPERATION: u64 = 2;
        pub const TRONA_INSUFFICIENT_RIGHTS: u64 = 3;
        pub const TRONA_INVALID_ARGUMENT: u64 = 4;
        pub const TRONA_OUT_OF_MEMORY: u64 = 5;
        pub const TRONA_NOT_FOUND: u64 = 6;
        pub const TRONA_BUSY: u64 = 7;
        pub const TRONA_ALREADY_EXISTS: u64 = 8;
        pub const TRONA_SLOT_OCCUPIED: u64 = 0x18;
        pub const TRONA_ALREADY_MAPPED: u64 = 0x19;
        pub const TRONA_ALREADY_BOUND: u64 = 0x1A;

        pub const SYS_CALL: u64 = 2;
        pub const SYS_YIELD: u64 = 8;
    }
}

pub mod protocol {
    pub mod procmgr {
        pub const PM_EXIT: u64 = 2;
        pub const PM_GETPID: u64 = 4;
    }

    pub mod vfs {
        pub const VFS_READ: u64 = 2;
        pub const VFS_WRITE: u64 = 3;
        pub const VFS_CLOSE: u64 = 4;
    }
}

pub mod types {
    pub mod core {
        include!("../uapi/types/core.rs");
    }
}

pub use types::core::{IpcBuffer, IpcContext, TronaMsg, TronaResult};

#[unsafe(no_mangle)]
pub static mut __trona_ipc_ctx: IpcContext = IpcContext::new();

#[unsafe(no_mangle)]
pub static mut __win32srv_ep: u64 = 0;

#[unsafe(no_mangle)]
pub static mut __trona_cap_procmgr_ep: u64 = 0;

#[unsafe(no_mangle)]
pub static mut __trona_cap_vfs_ep: u64 = 0;

pub fn current_ipc_ctx() -> *mut IpcContext {
    &raw mut __trona_ipc_ctx
}

pub mod caps {
    use super::{__trona_cap_procmgr_ep, __trona_cap_vfs_ep};

    pub fn procmgr_ep() -> u64 {
        unsafe { *(&raw const __trona_cap_procmgr_ep) }
    }

    pub fn vfs_ep() -> u64 {
        unsafe { *(&raw const __trona_cap_vfs_ep) }
    }
}

#[inline(always)]
pub fn msginfo(label: u64, length: u64, caps: u64) -> u64 {
    (label << 12) | (caps << 7) | (length & 0x7f)
}

pub mod syscall {
    use super::TronaResult;

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
}

pub mod ipc {
    use super::{
        consts::kernel::SYS_CALL, current_ipc_ctx, msginfo, syscall::syscall, IpcContext, TronaMsg,
    };

    unsafe fn clear_send_caps_ctx(ctx: *mut IpcContext) {
        unsafe {
            if ctx.is_null() {
                return;
            }
            let c = &mut *ctx;
            if !c.ipc_buffer.is_null() {
                for i in 0..4 {
                    (*c.ipc_buffer).caps[i] = 0;
                }
            }
            c.send_cap_count = 0;
        }
    }

    unsafe fn write_overflow_ctx(ctx: *mut IpcContext, msg: *const TronaMsg) {
        unsafe {
            let len = (*msg).length as usize;
            if ctx.is_null() || len <= 4 {
                return;
            }
            let c = &*ctx;
            if c.ipc_buffer.is_null() {
                return;
            }
            let n = core::cmp::min(len.saturating_sub(4), 28);
            for i in 0..n {
                (*c.ipc_buffer).msg[6 + i] = (*msg).regs[4 + i];
            }
        }
    }

    pub unsafe fn call_ctx(
        ctx: *mut IpcContext,
        ep: u64,
        msg: *const TronaMsg,
        reply: *mut TronaMsg,
    ) -> i32 {
        unsafe {
            let caps = if ctx.is_null() { 0 } else { (*ctx).send_cap_count };
            let info = msginfo((*msg).label, (*msg).length, caps as u64);
            write_overflow_ctx(ctx, msg);
            let r = syscall(
                SYS_CALL,
                ep,
                info,
                (*msg).regs[0],
                (*msg).regs[1],
                (*msg).regs[2],
                (*msg).regs[3],
            );
            if caps > 0 && !ctx.is_null() {
                clear_send_caps_ctx(ctx);
            }
            if r.error == 0 && !reply.is_null() {
                let active_ctx = if ctx.is_null() { current_ipc_ctx() } else { ctx };
                if !active_ctx.is_null() && !(*active_ctx).ipc_buffer.is_null() {
                    let buf = (*active_ctx).ipc_buffer as *const TronaMsg;
                    *reply = *buf;
                }
            }
            r.error as i32
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel32_runtime_init(
    ipc_buffer_vaddr: u64,
    win32srv_ep: u64,
    cap_procmgr_ep: u64,
    cap_vfs_ep: u64,
) {
    unsafe {
        let ctx = &raw mut __trona_ipc_ctx;
        (*ctx).ipc_buffer = ipc_buffer_vaddr as *mut IpcBuffer;
        (*ctx).send_cap_count = 0;
        *(&raw mut __win32srv_ep) = win32srv_ep;
        *(&raw mut __trona_cap_procmgr_ep) = cap_procmgr_ep;
        *(&raw mut __trona_cap_vfs_ep) = cap_vfs_ep;
        crate::handle::reset_handle_table();
        crate::console::reset_console_modes();
        crate::error::SetLastError(crate::error::ERROR_SUCCESS);
    }
}
