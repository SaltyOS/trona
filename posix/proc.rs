// SPDX-License-Identifier: GPL-2.0-only
//! POSIX process operations (exit, getpid, waitpid, execve, kill, clock_gettime).

use crate::WNOHANG;
use crate::*;
use trona_kernel::core_types::*;
use trona_protocol::posix::*;

const EXEC_MSG_MIN_SLOWPATH_LEN: usize = 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

impl Itimerval {
    pub const fn zeroed() -> Self {
        Itimerval {
            it_interval: Timeval::zeroed(),
            it_value: Timeval::zeroed(),
        }
    }
}

/// Terminate the current process with `status`.
///
/// Sends `INIT_EXIT` as a blocking Send (init does not reply) and then
/// issues `SYS_THREAD_EXIT` to stop this thread deterministically —
/// mirroring the `pm_thread_exit_send` + `thread_exit` tail of
/// `pthread_exit`. Auxiliary pthread teardown is init's responsibility
/// during INIT_EXIT via `RES_RECLAIM_OWNER`.
pub unsafe fn posix_exit(status: i32) -> ! {
    unsafe {
        crate::bulk::release_bulk_shm();
        let mut msg = TronaMsg::zeroed();
        msg.label = INIT_EXIT;
        msg.length = 1;
        msg.regs[0] = status as u64;

        let _ = trona_kernel::ipc::mp_write_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
        );

        trona_kernel::syscall::thread_exit()
    }
}

/// Return the process ID of the calling process.
pub unsafe fn posix_getpid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_PID;
        msg.length = 0;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the parent process ID of the calling process.
pub unsafe fn posix_getppid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_PPID;
        msg.length = 0;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

unsafe fn posix_waitpid_impl(pid: i32, status: *mut i32, options: i32, deadline_ns: u64) -> i32 {
    unsafe {
        loop {
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = INIT_WAIT;
            msg.length = if deadline_ns != 0 { 3 } else { 2 };
            msg.regs[0] = pid as u32 as u64;
            msg.regs[1] = options as u64;
            msg.regs[2] = deadline_ns;

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                trona_runtime::client::caps::init_ep().addr(),
                &raw const msg,
                &raw mut reply,
                // IPC deadline is infinite — init replies promptly (a result
                // or WOULD_BLOCK). The waitpid timeout itself rides
                // `msg.regs[2]` (deadline_ns) + the client re-poll loop below.
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            // No RESTART/INTERRUPTED re-send: the kernel reply-wait
            // (register-at-send + readiness) owns resume; re-sending would
            // duplicate a non-idempotent request.
            if err != 0 {
                return super::call_err_to_posix(err);
            }
            if reply.label == (uapi::KERNITE_ERR_WOULD_BLOCK as u64) {
                if (options as u64 & WNOHANG) != 0 {
                    return 0;
                }
                if deadline_ns != 0 {
                    let now = trona_kernel::syscall::clock_read_monotonic(
                        trona_runtime::client::caps::clock_cap().addr(),
                    );
                    if now >= deadline_ns {
                        return -110; // ETIMEDOUT
                    }
                }
                trona_kernel::syscall::yield_now();
                continue;
            }
            if reply.label != (uapi::KERNITE_OK as u64) {
                return super::trona_err_to_posix(reply.label);
            }

            if !status.is_null() {
                *status = reply.regs[1] as i32;
            }
            return reply.regs[0] as i32;
        }
    }
}

/// Wait for a child process to change state.
///
/// `pid` selects which child (-1 = any). `options` may include
/// `WNOHANG`, `WUNTRACED`, and `WCONTINUED`.
/// On success, writes the wait status to `*status` and returns the child PID.
/// Returns -1 on error.
pub unsafe fn posix_waitpid3(pid: i32, status: *mut i32, options: i32) -> i32 {
    unsafe { posix_waitpid_impl(pid, status, options, 0) }
}

/// Deadline-aware waitpid variant.
///
/// `deadline_ns` is an absolute CLOCK_MONOTONIC deadline in nanoseconds.
/// Returns `-ETIMEDOUT` when the child has not changed state by the deadline.
pub unsafe fn posix_waitpid_deadline_ns(
    pid: i32,
    status: *mut i32,
    options: i32,
    deadline_ns: u64,
) -> i32 {
    unsafe { posix_waitpid_impl(pid, status, options, deadline_ns) }
}

/// Convenience wrapper for `posix_waitpid3` with `options=0` (blocking).
pub unsafe fn posix_waitpid(pid: i32, status: *mut i32) -> i32 {
    unsafe { posix_waitpid3(pid, status, 0) }
}

/// Replace the current process image with a new program.
///
/// Packs the executable path, argv, and envp into a single IPC message to
/// the process manager. The path and argc/envc metadata travel in message
/// registers; argv/envp string bytes are staged in the IPC buffer's reserved
/// payload area so large environments are not silently truncated.
/// Returns 0 on success (caller is replaced), -errno on error.
pub unsafe fn posix_execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    unsafe {
        // Resolve the binary under our own VFS authority and receive its
        // non-exec backing MemoryObject; forwarded to init on caps[0] below.
        // The MO lands in a sticky receive slot, rearmed on the next exec.
        // Doing this first fails fast (ENOENT/EACCES) before building the request.
        let (exec_mo_slot, exec_size, exec_offset) =
            match trona_runtime::client::vfs::open_for_exec(path) {
                Ok(opened) => opened,
                Err(e) => return super::trona_err_to_posix(e),
            };
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_EXEC;

        let mut path_len: u8 = 0;
        while path_len < 64 && *path.add(path_len as usize) != 0 {
            path_len += 1;
        }
        if path_len == 64 && *path.add(path_len as usize) != 0 {
            trona_runtime::client::vfs::clear_exec_mo_recv_slot(exec_mo_slot);
            return -36; // ENAMETOOLONG
        }

        // regs[0] = path_len
        msg.regs[0] = path_len as u64;
        let dst = &mut msg.regs[1] as *mut u64 as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path.add(i);
        }
        let path_regs = 1 + ((path_len as u64 + 7) / 8) as usize;

        // Count argc and envc, and total string data length
        let mut argc: u32 = 0;
        let mut envc: u32 = 0;
        let mut total_str_len: usize = 0;

        if !argv.is_null() {
            let mut i = 0;
            while !(*argv.add(i)).is_null() {
                let mut slen = 0usize;
                while *(*argv.add(i)).add(slen) != 0 {
                    slen += 1;
                }
                total_str_len += slen + 1; // include null terminator
                argc += 1;
                i += 1;
            }
        }
        if !envp.is_null() {
            let mut i = 0;
            while !(*envp.add(i)).is_null() {
                let mut slen = 0usize;
                while *(*envp.add(i)).add(slen) != 0 {
                    slen += 1;
                }
                total_str_len += slen + 1;
                envc += 1;
                i += 1;
            }
        }

        // regs[path_regs] = (argc << 32) | envc
        let next = path_regs;
        msg.regs[next] = ((argc as u64) << 32) | (envc as u64);

        if total_str_len > IPC_BUFFER_RESERVED_BYTES {
            trona_runtime::client::vfs::clear_exec_mo_recv_slot(exec_mo_slot);
            return -7; // E2BIG
        }

        let ctx = crate::tls::current_ipc_ctx();
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            trona_runtime::client::vfs::clear_exec_mo_recv_slot(exec_mo_slot);
            return -5; // EIO
        }

        // regs[path_regs + 1] = total argv/envp payload bytes in ipc_buffer.reserved[]
        msg.regs[next + 1] = total_str_len as u64;
        // regs[path_regs + 2] = exact executable byte size from VFS_OPEN_FOR_EXEC.
        msg.regs[next + 2] = exec_size;
        // regs[path_regs + 3] = executable byte offset within the backing MO.
        msg.regs[next + 3] = exec_offset;
        msg.length = ::core::cmp::max(next + 4, EXEC_MSG_MIN_SLOWPATH_LEN) as u64;

        let ipc_buf = &mut *(*ctx).ipc_buffer;
        let str_dst = ipc_buf.reserved.as_mut_ptr() as *mut u8;
        let mut pos = 0usize;

        if !argv.is_null() {
            let mut i = 0;
            while !(*argv.add(i)).is_null() {
                let arg = *argv.add(i);
                let mut j = 0usize;
                while *arg.add(j) != 0 {
                    *str_dst.add(pos) = *arg.add(j);
                    pos += 1;
                    j += 1;
                }
                *str_dst.add(pos) = 0;
                pos += 1;
                i += 1;
            }
        }
        if !envp.is_null() {
            let mut i = 0;
            while !(*envp.add(i)).is_null() {
                let env = *envp.add(i);
                let mut j = 0usize;
                while *env.add(j) != 0 {
                    *str_dst.add(pos) = *env.add(j);
                    pos += 1;
                    j += 1;
                }
                *str_dst.add(pos) = 0;
                pos += 1;
                i += 1;
            }
        }
        debug_assert_eq!(pos, total_str_len);

        // Forward the exec MO to init as caps[0] of this INIT_EXEC send
        // (the kernel MOVEs it out of the receive slot).
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
        trona_kernel::ipc::set_send_cap_ctx(ctx, 0, exec_mo_slot);
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
        if err != 0 {
            trona_runtime::client::vfs::clear_exec_mo_recv_slot(exec_mo_slot);
            return super::call_err_to_posix(err);
        }
        if reply.label == (uapi::KERNITE_ERR_OUT_OF_RANGE as u64) {
            trona_runtime::client::vfs::clear_exec_mo_recv_slot(exec_mo_slot);
            return -7; // E2BIG
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            trona_runtime::client::vfs::clear_exec_mo_recv_slot(exec_mo_slot);
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Send signal `sig` to process `pid`. Returns 0 on success, -1 on error.
pub unsafe fn posix_kill(pid: i32, sig: i32) -> i32 {
    unsafe {
        loop {
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = INIT_KILL;
            msg.length = 2;
            msg.regs[0] = pid as u32 as u64;
            msg.regs[1] = sig as u64;

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                trona_runtime::client::caps::init_ep().addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            // No RESTART/INTERRUPTED re-send: the kernel reply-wait
            // (register-at-send + readiness) owns resume; re-sending would
            // duplicate a non-idempotent request.
            if err != 0 {
                return super::call_err_to_posix(err);
            }
            if reply.label != (uapi::KERNITE_OK as u64) {
                return super::trona_err_to_posix(reply.label);
            }
            return 0;
        }
    }
}

// Fork the current process, returning the child PID to the parent and 0
// to the child. Defined in `fork.S` (assembly trampoline that issues the
// INIT_FORK IPC and re-initializes the child's IPC context).
unsafe extern "C" {
    pub safe fn posix_fork() -> i32;
}

/// Set the process group ID of process `pid` to `pgid`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_setpgid(pid: i32, pgid: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_PGRP_SESSION;
        msg.length = 3;
        msg.regs[0] = INIT_PGRP_SUB_SETPGID;
        msg.regs[1] = pid as u32 as u64;
        msg.regs[2] = pgid as u32 as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Get the process group ID of process `pid`. Returns pgid or -1 on error.
pub unsafe fn posix_getpgid(pid: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_PGRP_SESSION;
        msg.length = 2;
        msg.regs[0] = INIT_PGRP_SUB_GETPGID;
        msg.regs[1] = pid as u32 as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Create a new session and set the process as session leader.
/// Returns the new session ID, or -1 on error.
pub unsafe fn posix_setsid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_PGRP_SESSION;
        msg.length = 1;
        msg.regs[0] = INIT_PGRP_SUB_SETSID;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Get the session ID of process `pid` (or caller when `pid==0`).
/// Returns sid on success, -1 on error.
pub unsafe fn posix_getsid(pid: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_PGRP_SESSION;
        msg.length = 2;
        msg.regs[0] = INIT_PGRP_SUB_GETSID;
        msg.regs[1] = pid as u32 as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the calling process's controlling terminal device id.
///
/// On success returns a non-negative synthetic `tty_dev` id (see
/// `crate::{TTY_DEV_CONSOLE, TTY_DEV_PTS_BASE}`). On error
/// returns `-errno`.
pub unsafe fn posix_get_session_tty_dev() -> i64 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_GET_CTTY_DEV;
        msg.length = 0;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err) as i64;
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label) as i64;
        }
        reply.regs[0] as i64
    }
}

/// Return the real user ID of the calling process.
pub unsafe fn posix_getuid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 1;
        msg.regs[0] = INIT_CRED_SUB_GETUID;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the effective user ID of the calling process.
pub unsafe fn posix_geteuid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 1;
        msg.regs[0] = INIT_CRED_SUB_GETEUID;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the real group ID of the calling process.
pub unsafe fn posix_getgid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 1;
        msg.regs[0] = INIT_CRED_SUB_GETGID;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the effective group ID of the calling process.
pub unsafe fn posix_getegid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 1;
        msg.regs[0] = INIT_CRED_SUB_GETEGID;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Get supplementary group IDs. Returns the number of groups, or -1 on error.
pub unsafe fn posix_getgroups(size: i32, _list: *mut i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 2;
        msg.regs[0] = INIT_CRED_SUB_GETGROUPS;
        msg.regs[1] = size as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

pub unsafe fn posix_setuid(uid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 2;
        msg.regs[0] = INIT_CRED_SUB_SETUID;
        msg.regs[1] = uid as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_setgid(gid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 2;
        msg.regs[0] = INIT_CRED_SUB_SETGID;
        msg.regs[1] = gid as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_seteuid(euid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 2;
        msg.regs[0] = INIT_CRED_SUB_SETEUID;
        msg.regs[1] = euid as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_setegid(egid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 2;
        msg.regs[0] = INIT_CRED_SUB_SETEGID;
        msg.regs[1] = egid as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_setreuid(ruid: u32, euid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 3;
        msg.regs[0] = INIT_CRED_SUB_SETREUID;
        msg.regs[1] = ruid as u64;
        msg.regs[2] = euid as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_setregid(rgid: u32, egid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 3;
        msg.regs[0] = INIT_CRED_SUB_SETREGID;
        msg.regs[1] = rgid as u64;
        msg.regs[2] = egid as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_setgroups(ngroups: usize, groups: *const u32) -> i32 {
    unsafe {
        if ngroups > 32 {
            return -22;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.regs[0] = INIT_CRED_SUB_SETGROUPS;
        msg.regs[1] = ngroups as u64;
        let mut gi = 0usize;
        let mut ri = 2usize;
        while gi < ngroups {
            msg.regs[ri] = *groups.add(gi) as u64;
            gi += 1;
            ri += 1;
        }
        msg.length = ri as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 1;
        msg.regs[0] = INIT_CRED_SUB_GETRESUID;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        if !ruid.is_null() {
            *ruid = reply.regs[0] as u32;
        }
        if !euid.is_null() {
            *euid = reply.regs[1] as u32;
        }
        if !suid.is_null() {
            *suid = reply.regs[2] as u32;
        }
        0
    }
}

pub unsafe fn posix_getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 1;
        msg.regs[0] = INIT_CRED_SUB_GETRESGID;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        if !rgid.is_null() {
            *rgid = reply.regs[0] as u32;
        }
        if !egid.is_null() {
            *egid = reply.regs[1] as u32;
        }
        if !sgid.is_null() {
            *sgid = reply.regs[2] as u32;
        }
        0
    }
}

pub unsafe fn posix_setresuid(ruid: u32, euid: u32, suid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 4;
        msg.regs[0] = INIT_CRED_SUB_SETRESUID;
        msg.regs[1] = ruid as u64;
        msg.regs[2] = euid as u64;
        msg.regs[3] = suid as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_setresgid(rgid: u32, egid: u32, sgid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_CRED;
        msg.length = 4;
        msg.regs[0] = INIT_CRED_SUB_SETRESGID;
        msg.regs[1] = rgid as u64;
        msg.regs[2] = egid as u64;
        msg.regs[3] = sgid as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_getrlimit(resource: u32, rlim_cur: *mut u64, rlim_max: *mut u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_RLIMIT;
        msg.length = 2;
        msg.regs[0] = INIT_RLIMIT_SUB_GET;
        msg.regs[1] = resource as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        if !rlim_cur.is_null() {
            *rlim_cur = reply.regs[0];
        }
        if !rlim_max.is_null() {
            *rlim_max = reply.regs[1];
        }
        0
    }
}

pub unsafe fn posix_setrlimit(resource: u32, rlim_cur: u64, rlim_max: u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_RLIMIT;
        msg.length = 4;
        msg.regs[0] = INIT_RLIMIT_SUB_SET;
        msg.regs[1] = resource as u64;
        msg.regs[2] = rlim_cur;
        msg.regs[3] = rlim_max;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

pub unsafe fn posix_setitimer(
    which: i32,
    new_value: *const Itimerval,
    old_value: *mut Itimerval,
) -> i32 {
    unsafe {
        if new_value.is_null() {
            return -14; // EFAULT
        }

        let new_value = &*new_value;
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_ITIMER;
        msg.length = 4;
        msg.regs[0] = INIT_ITIMER_SUB_SET;
        msg.regs[1] = which as u64;
        msg.regs[2] = new_value
            .it_interval
            .tv_sec
            .saturating_mul(1_000_000_000)
            .saturating_add(new_value.it_interval.tv_usec.saturating_mul(1_000));
        msg.regs[3] = new_value
            .it_value
            .tv_sec
            .saturating_mul(1_000_000_000)
            .saturating_add(new_value.it_value.tv_usec.saturating_mul(1_000));

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }

        if !old_value.is_null() {
            (*old_value).it_interval.tv_sec = reply.regs[0] / 1_000_000_000;
            (*old_value).it_interval.tv_usec = (reply.regs[0] % 1_000_000_000) / 1_000;
            (*old_value).it_value.tv_sec = reply.regs[1] / 1_000_000_000;
            (*old_value).it_value.tv_usec = (reply.regs[1] % 1_000_000_000) / 1_000;
        }
        0
    }
}

pub unsafe fn posix_getitimer(which: i32, curr_value: *mut Itimerval) -> i32 {
    unsafe {
        if curr_value.is_null() {
            return -14; // EFAULT
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_ITIMER;
        msg.length = 2;
        msg.regs[0] = INIT_ITIMER_SUB_GET;
        msg.regs[1] = which as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }

        (*curr_value).it_interval.tv_sec = reply.regs[0] / 1_000_000_000;
        (*curr_value).it_interval.tv_usec = (reply.regs[0] % 1_000_000_000) / 1_000;
        (*curr_value).it_value.tv_sec = reply.regs[1] / 1_000_000_000;
        (*curr_value).it_value.tv_usec = (reply.regs[1] % 1_000_000_000) / 1_000;
        0
    }
}

/// Read a clock through the process's `Clock` cap.
///
/// `clock_id` is a POSIX `clockid_t` (`CLOCK_REALTIME` /
/// `CLOCK_MONOTONIC`); the kernel-side mapping lives in
/// `uapi::KERNITE_CLOCK_ID_*` and the `Clock` cap is delivered to
/// every process by the spawner via `ROLE_CLOCK`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_clock_gettime(clock_id: i32, ts: *mut crate::types::Timespec) -> i32 {
    unsafe {
        let clock_cap = trona_runtime::client::caps::clock_cap().addr();
        let ns = match clock_id {
            crate::CLOCK_MONOTONIC => trona_kernel::syscall::clock_read_monotonic(clock_cap),
            crate::CLOCK_REALTIME => trona_kernel::syscall::clock_read_realtime(clock_cap),
            _ => return -1,
        };
        (*ts).tv_sec = ns / 1_000_000_000;
        (*ts).tv_nsec = ns % 1_000_000_000;
        0
    }
}

/// Get the current realtime as seconds + microseconds into `*tv`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_gettimeofday(tv: *mut crate::types::Timeval) -> i32 {
    unsafe {
        let ns = trona_kernel::syscall::clock_read_realtime(
            trona_runtime::client::caps::clock_cap().addr(),
        );
        (*tv).tv_sec = ns / 1_000_000_000;
        (*tv).tv_usec = (ns % 1_000_000_000) / 1_000;
        0
    }
}

/// Block the current thread until the absolute monotonic deadline
/// `deadline_ns` is reached, returning early with `-EINTR` if a
/// signal is delivered before then.
///
/// Drives the new ABI's event plane via `crate::wakeup`:
///
/// 1. `wakeup::arm_sleep_timer(deadline_ns)` schedules a TIMER record
///    in the per-process wakeup `EventQueue`.
/// 2. `wakeup::wait_record()` blocks in `EQ_WAIT` until either:
///    - a TIMER record (cookie `WAKEUP_COOKIE_TIMER`) — sleep done; or
///    - a STATE record from the signal-pipe Watch (cookie
///      `WAKEUP_COOKIE_SIGNAL_PIPE`) — drain the pipe, dispatch
///      handlers, and either resume (if all dispatched signals had
///      `SA_RESTART`) or return `-EINTR`.
///
/// Returns 0 on natural timer expiry, -1 on retype/invocation
/// failure, `-uapi::KERNITE_ERR_INTERRUPTED` on signal interrupt.
unsafe fn sleep_until(deadline_ns: u64) -> i32 {
    if wakeup::arm_sleep_timer(deadline_ns) != 0 {
        return -1;
    }
    loop {
        let rec = match wakeup::wait_record() {
            Some(r) => r,
            None => return -1,
        };
        if rec.cookie == wakeup::WAKEUP_COOKIE_TIMER {
            return 0;
        }
        if rec.cookie == wakeup::WAKEUP_COOKIE_SIGNAL_PIPE {
            wakeup::drain_signal_pipe();
            unsafe {
                crate::signals::posix_sigcheck();
                let restartable = *(&raw const crate::__sig_last_restart);
                if !restartable {
                    wakeup::cancel_sleep_timer();
                    return -(uapi::KERNITE_ERR_INTERRUPTED as i32);
                }
            }
            // SA_RESTART path: timer is still armed, resume waiting.
        }
    }
}

/// Block for `timeout_ns` nanoseconds via the per-process Timer.
/// Returns 0 on success, -1 on error,
/// `-uapi::KERNITE_ERR_INTERRUPTED` on signal interrupt.
unsafe fn sleep_for(timeout_ns: u64) -> i32 {
    if timeout_ns == 0 {
        return 0;
    }
    let deadline_ns = trona_kernel::syscall::clock_read_monotonic(
        trona_runtime::client::caps::clock_cap().addr(),
    )
    .saturating_add(timeout_ns);
    unsafe { sleep_until(deadline_ns) }
}

/// Sleep for the duration specified in `*req`.
/// If `rem` is non-null, any remaining time after interruption is
/// written there (always zero in current implementation — the new
/// event-plane wait blocks on a single TIMER record so partial
/// completion is not observable). Returns 0 on success.
pub unsafe fn posix_nanosleep(
    req: *const crate::types::Timespec,
    rem: *mut crate::types::Timespec,
) -> i32 {
    unsafe {
        let timeout_ns = ((*req).tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add((*req).tv_nsec as u64);
        if !rem.is_null() {
            (*rem).tv_sec = 0;
            (*rem).tv_nsec = 0;
        }
        sleep_for(timeout_ns)
    }
}

/// Sleep for `usec` microseconds. Returns 0 on success, -1 on error.
pub unsafe fn posix_usleep(usec: u64) -> i32 {
    unsafe { sleep_for(usec.saturating_mul(1_000)) }
}

/// Sleep for `seconds`. Returns 0 on success, or remaining seconds on error.
pub unsafe fn posix_sleep(seconds: u64) -> u64 {
    let timeout_ns = seconds.saturating_mul(1_000_000_000);
    if unsafe { sleep_for(timeout_ns) } != 0 {
        seconds
    } else {
        0
    }
}
