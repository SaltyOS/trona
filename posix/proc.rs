// SPDX-License-Identifier: GPL-2.0-only
//! POSIX process operations (exit, getpid, waitpid, execve, kill, clock_gettime).

use trona::consts::kernel::*;
use trona::protocol::*;
use trona::types::core::*;

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
/// Sends `PM_EXIT` to the process manager via blocking Call. The procmgr
/// never replies -- the child stays in ReplyWait until TCB_SUSPEND moves
/// it to Inactive. This avoids the yield-loop that starves SCHED_IPC_LOCK
/// on SMP.
pub unsafe fn posix_exit(status: i32) -> ! {
    unsafe {
        // pthread teardown is now procmgr's responsibility — auxiliary
        // threads are reaped via RES_RECLAIM_OWNER inside PM_EXIT.

        let mut msg = TronaMsg::zeroed();
        msg.label = PM_EXIT;
        msg.length = 1;
        msg.regs[0] = status as u64;

        // Call blocks waiting for reply; procmgr never replies for PM_EXIT,
        // so the child stays in ReplyWait until TCB_SUSPEND moves it to Inactive.
        // This avoids the yield-loop that starves SCHED_IPC_LOCK on SMP.
        let mut reply = TronaMsg::zeroed();
        crate::ipc_call_retry(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
    }
    // Unreachable: call never returns since procmgr never replies
    loop {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

/// Return the process ID of the calling process.
pub unsafe fn posix_getpid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_GETPID;
        msg.length = 0;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
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
        msg.label = PM_GETPPID;
        msg.length = 0;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Wait for a child process to change state.
///
/// `pid` selects which child (-1 = any). `options` may include WNOHANG.
/// On success, writes the wait status to `*status` and returns the child PID.
/// Returns -1 on error.
pub unsafe fn posix_waitpid3(pid: i32, status: *mut i32, options: i32) -> i32 {
    unsafe {
        loop {
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = PM_WAIT;
            msg.length = 2;
            msg.regs[0] = pid as u32 as u64;
            msg.regs[1] = options as u64;

            let err = trona::ipc::call_ctx(
                crate::tls::current_ipc_ctx(),
                trona::caps::procmgr_ep(),
                &raw const msg,
                &raw mut reply,
            );
            if err == TRONA_RESTART as i32 {
                // CallSendBlocked — procmgr never received. Always retry.
                continue;
            }
            if err == TRONA_INTERRUPTED as i32 {
                // ReplyWait — procmgr received but reply was dropped.
                // procmgr preserves the zombie when send fails.
                if *(&raw const crate::__sig_last_restart) {
                    continue; // SA_RESTART: retry
                }
                return -4; // EINTR
            }
            if err != 0 {
                return super::call_err_to_posix(err);
            }
            if reply.label != TRONA_OK {
                return super::trona_err_to_posix(reply.label);
            }

            if !status.is_null() {
                *status = reply.regs[0] as i32;
            }
            return reply.regs[1] as i32;
        }
    }
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
pub unsafe fn posix_execve(
    path: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_EXEC;

        let mut path_len: u8 = 0;
        while *path.add(path_len as usize) != 0 && path_len < 64 {
            path_len += 1;
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
            return -7; // E2BIG
        }

        let ctx = crate::tls::current_ipc_ctx();
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            return -5; // EIO
        }

        // regs[path_regs + 1] = total argv/envp payload bytes in ipc_buffer.reserved[]
        msg.regs[next + 1] = total_str_len as u64;
        msg.length = ::core::cmp::max(next + 2, EXEC_MSG_MIN_SLOWPATH_LEN) as u64;

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

        let err = crate::ipc_call_retry(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label == TRONA_OUT_OF_RANGE {
            return -7; // E2BIG
        }
        if reply.label != TRONA_OK {
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
            msg.label = PM_KILL;
            msg.length = 2;
            msg.regs[0] = pid as u32 as u64;
            msg.regs[1] = sig as u64;

            let err = trona::ipc::call_ctx(
                crate::tls::current_ipc_ctx(),
                trona::caps::procmgr_ep(),
                &raw const msg,
                &raw mut reply,
            );
            if err == TRONA_RESTART as i32 {
                // CallSendBlocked — procmgr never received. Retry.
                continue;
            }
            if err == TRONA_INTERRUPTED as i32 {
                // ReplyWait — procmgr already processed the kill.
                // kill() is idempotent (notification bit OR) and POSIX
                // says kill() never returns EINTR. Return success.
                return 0;
            }
            if err != 0 {
                return super::call_err_to_posix(err);
            }
            if reply.label != TRONA_OK {
                return super::trona_err_to_posix(reply.label);
            }
            return 0;
        }
    }
}

// Fork the current process, returning the child PID to the parent and 0
// to the child. Defined in `fork.S` (assembly trampoline that issues the
// PM_FORK IPC and re-initializes the child's IPC context).
unsafe extern "C" {
    pub safe fn posix_fork() -> i32;
}

/// Set the process group ID of process `pid` to `pgid`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_setpgid(pid: i32, pgid: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETPGID;
        msg.length = 2;
        msg.regs[0] = pid as u32 as u64;
        msg.regs[1] = pgid as u32 as u64;

        let err = crate::ipc_call_retry(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
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
        msg.label = PM_GETPGID;
        msg.length = 1;
        msg.regs[0] = pid as u32 as u64;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
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
        msg.label = PM_SETSID;
        msg.length = 0;

        let err = crate::ipc_call_retry(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
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
        msg.label = PM_GETSID;
        msg.length = 1;
        msg.regs[0] = pid as u32 as u64;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the real user ID of the calling process.
pub unsafe fn posix_getuid() -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_GETUID;
        msg.length = 0;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
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
        msg.label = PM_GETEUID;
        msg.length = 0;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
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
        msg.label = PM_GETGID;
        msg.length = 0;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
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
        msg.label = PM_GETEGID;
        msg.length = 0;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
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
        msg.label = PM_GETGROUPS;
        msg.length = 1;
        msg.regs[0] = size as u64;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

pub unsafe fn posix_setuid(uid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETUID;
        msg.length = 1;
        msg.regs[0] = uid as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_setgid(gid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETGID;
        msg.length = 1;
        msg.regs[0] = gid as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_seteuid(euid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETEUID;
        msg.length = 1;
        msg.regs[0] = euid as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_setegid(egid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETEGID;
        msg.length = 1;
        msg.regs[0] = egid as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_setreuid(ruid: u32, euid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETREUID;
        msg.length = 2;
        msg.regs[0] = ruid as u64;
        msg.regs[1] = euid as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_setregid(rgid: u32, egid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETREGID;
        msg.length = 2;
        msg.regs[0] = rgid as u64;
        msg.regs[1] = egid as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_setgroups(ngroups: usize, groups: *const u32) -> i32 {
    unsafe {
        if ngroups > 32 { return -22; }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETGROUPS;
        msg.regs[0] = ngroups as u64;
        let mut gi = 0usize;
        let mut ri = 1usize;
        while gi < ngroups {
            let lo = *groups.add(gi) as u64;
            gi += 1;
            let hi = if gi < ngroups { let v = *groups.add(gi) as u64; gi += 1; v } else { 0 };
            msg.regs[ri] = lo | (hi << 32);
            ri += 1;
        }
        msg.length = ri as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_GETRESUID;
        msg.length = 0;
        let err = crate::ipc_call_retry_idempotent(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        if !ruid.is_null() { *ruid = reply.regs[0] as u32; }
        if !euid.is_null() { *euid = reply.regs[1] as u32; }
        if !suid.is_null() { *suid = reply.regs[2] as u32; }
        0
    }
}

pub unsafe fn posix_getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_GETRESGID;
        msg.length = 0;
        let err = crate::ipc_call_retry_idempotent(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        if !rgid.is_null() { *rgid = reply.regs[0] as u32; }
        if !egid.is_null() { *egid = reply.regs[1] as u32; }
        if !sgid.is_null() { *sgid = reply.regs[2] as u32; }
        0
    }
}

pub unsafe fn posix_setresuid(ruid: u32, euid: u32, suid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETRESUID;
        msg.length = 3;
        msg.regs[0] = ruid as u64;
        msg.regs[1] = euid as u64;
        msg.regs[2] = suid as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_setresgid(rgid: u32, egid: u32, sgid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETRESGID;
        msg.length = 3;
        msg.regs[0] = rgid as u64;
        msg.regs[1] = egid as u64;
        msg.regs[2] = sgid as u64;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        0
    }
}

pub unsafe fn posix_getrlimit(resource: u32, rlim_cur: *mut u64, rlim_max: *mut u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_GETRLIMIT;
        msg.length = 1;
        msg.regs[0] = resource as u64;
        let err = crate::ipc_call_retry_idempotent(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
        if !rlim_cur.is_null() { *rlim_cur = reply.regs[0]; }
        if !rlim_max.is_null() { *rlim_max = reply.regs[1]; }
        0
    }
}

pub unsafe fn posix_setrlimit(resource: u32, rlim_cur: u64, rlim_max: u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SETRLIMIT;
        msg.length = 3;
        msg.regs[0] = resource as u64;
        msg.regs[1] = rlim_cur;
        msg.regs[2] = rlim_max;
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const msg, &raw mut reply);
        if err != 0 { return super::call_err_to_posix(err); }
        if reply.label != TRONA_OK { return super::trona_err_to_posix(reply.label); }
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
        msg.label = PM_SETITIMER;
        msg.length = 5;
        msg.regs[0] = which as u64;
        msg.regs[1] = new_value.it_value.tv_sec;
        msg.regs[2] = new_value.it_value.tv_usec;
        msg.regs[3] = new_value.it_interval.tv_sec;
        msg.regs[4] = new_value.it_interval.tv_usec;

        let err = crate::ipc_call_retry(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }

        if !old_value.is_null() {
            (*old_value).it_value.tv_sec = reply.regs[0];
            (*old_value).it_value.tv_usec = reply.regs[1];
            (*old_value).it_interval.tv_sec = reply.regs[2];
            (*old_value).it_interval.tv_usec = reply.regs[3];
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
        msg.label = PM_GETITIMER;
        msg.length = 1;
        msg.regs[0] = which as u64;

        let err = crate::ipc_call_retry_idempotent(
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }

        (*curr_value).it_value.tv_sec = reply.regs[0];
        (*curr_value).it_value.tv_usec = reply.regs[1];
        (*curr_value).it_interval.tv_sec = reply.regs[2];
        (*curr_value).it_interval.tv_usec = reply.regs[3];
        0
    }
}

/// Read the monotonic clock, writing seconds and nanoseconds into `*ts`.
/// Uses the kernel `SYS_CLOCK_GETTIME` syscall directly (no IPC).
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_clock_gettime(clock_id: i32, ts: *mut trona::types::core::Timespec) -> i32 {
    unsafe {
        let res = trona::syscall::syscall(SYS_CLOCK_GETTIME, clock_id as u64, 0, 0, 0, 0, 0);
        if res.error != 0 {
            return -1;
        }
        let ns = res.value;
        (*ts).tv_sec = ns / 1_000_000_000;
        (*ts).tv_nsec = ns % 1_000_000_000;
        0
    }
}

/// Get the current time as seconds + microseconds into `*tv`.
/// Uses the kernel clock syscall, converting nanoseconds to microseconds.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_gettimeofday(tv: *mut trona::types::core::Timeval) -> i32 {
    unsafe {
        let res = trona::syscall::syscall(SYS_CLOCK_GETTIME, 0, 0, 0, 0, 0, 0);
        if res.error != 0 {
            return -1;
        }
        let ns = res.value;
        (*tv).tv_sec = ns / 1_000_000_000;
        (*tv).tv_usec = (ns % 1_000_000_000) / 1_000;
        0
    }
}

/// Sleep for the duration specified in `*req`.
/// If `rem` is non-null, any remaining time after interruption is written
/// there (always zero in current implementation). Returns 0 on success.
pub unsafe fn posix_nanosleep(req: *const trona::types::core::Timespec, rem: *mut trona::types::core::Timespec) -> i32 {
    unsafe {
        let seconds = (*req).tv_sec;
        let nanos = (*req).tv_nsec;
        let res = trona::syscall::syscall(SYS_NANOSLEEP, seconds, nanos, 0, 0, 0, 0);
        if !rem.is_null() {
            (*rem).tv_sec = 0;
            (*rem).tv_nsec = 0;
        }
        if res.error != 0 {
            return -1;
        }
        0
    }
}

/// Sleep for `usec` microseconds. Returns 0 on success, -1 on error.
pub unsafe fn posix_usleep(usec: u64) -> i32 {
    let seconds = usec / 1_000_000;
    let nanos = (usec % 1_000_000) * 1_000;
    let res = trona::syscall::syscall(SYS_NANOSLEEP, seconds, nanos, 0, 0, 0, 0);
    if res.error != 0 { -1 } else { 0 }
}

/// Sleep for `seconds`. Returns 0 on success, or remaining seconds on error.
pub unsafe fn posix_sleep(seconds: u64) -> u64 {
    let res = trona::syscall::syscall(SYS_NANOSLEEP, seconds, 0, 0, 0, 0, 0);
    if res.error != 0 { seconds } else { 0 }
}
