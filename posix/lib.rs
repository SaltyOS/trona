//! trona_posix -- POSIX compatibility layer for SaltyOS
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! This crate provides POSIX-compatible wrappers built on top of the `trona`
//! substrate (kernel ABI, IPC, capability invocations). Every POSIX operation
//! is implemented as an IPC `Call` to a userspace server (VFS, init, mmsrv).
//!
//! # Modules
//!
//! - **`file`** -- File I/O (open, read, write, stat, lseek, etc.)
//! - **`socket`** -- Sockets (socket, bind, listen, accept, connect, etc.)
//! - **`proc`** -- Process management (exec, waitpid, exit, etc.)
//! - **`pipe`** -- Pipes (pipe, pipe2)
//! - **`poll`** -- Polling (poll, epoll, select)
//! - **`mm`** -- Memory management (mmap, munmap, shm)
//! - **`signals`** -- POSIX signal delivery via the per-thread wakeup
//!   `EventQueue` + signal-pipe `Watch` (see `wakeup`)
//! - **`wakeup`** -- Per-thread `EventQueue` / `Timer` / signal-pipe
//!   `Watch` plumbing for sleep + signal dispatch
//! - **`pthread`** -- POSIX threads (create, join, exit, detach, mutex, key)
//! - **`tls`** -- Thread-Local Storage block layout and accessors
//! - **`dns`** -- DNS hostname resolution client
//! - **`at`** -- *at() family (openat, fstatat, etc.)
//! - **`misc`** -- Miscellaneous (umask, uname, etc.)
//! - **`bulk`** -- Bulk I/O helpers
//!
//! # Global state
//!
//! Signal handler tables and masks are defined here so they are accessible
//! from both `signals` and C ABI exports.

#![no_std]
#![allow(internal_features)]

extern crate trona_kernel;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

use core::sync::atomic::{AtomicU64, Ordering};
use trona_protocol::common::{
    TRONA_ALREADY_EXISTS, TRONA_BAD_ADDRESS, TRONA_BUSY, TRONA_CANCELLED, TRONA_DEADLOCK,
    TRONA_INVALID_ARGUMENT, TRONA_INVALID_CAPABILITY, TRONA_INVALID_OPERATION, TRONA_IO_ERROR,
    TRONA_NOT_FOUND, TRONA_NOT_SUPPORTED, TRONA_OUT_OF_MEMORY, TRONA_OUT_OF_RANGE,
    TRONA_PERMISSION_DENIED, TRONA_READONLY, TRONA_TIMED_OUT, TRONA_TOO_LARGE, TRONA_WOULD_BLOCK,
};

pub mod at;
pub(crate) mod bulk;
pub mod consts;
pub mod dns;
pub mod file;
pub mod misc;
pub mod mm;
pub mod pipe;
pub mod poll;
pub mod proc;
pub mod pthread;
pub mod signals;
pub mod socket;
pub mod tls;
pub mod types;
pub mod wakeup;

pub use at::*;
pub use file::*;
pub use misc::*;
pub use pipe::*;
pub use poll::*;
pub use proc::*;
pub use socket::*;

// Substrate-side SaltyOS startup contract types.
pub use trona_kernel::core_types::*;

// POSIX-personality consts/types live in this crate.
pub use crate::consts::*;
pub use crate::types::*;
pub use trona_protocol::posix::*;

static NEXT_FORK_TXID: AtomicU64 = AtomicU64::new(1);

/// Convert a server error label to a negative POSIX errno code.
///
/// The wire labels carried in `TronaMsg.label` come from two namespaces:
///
/// - **Kernel ABI** — `KERNITE_OK` / `KERNITE_ERR_*`, defined by the
///   kernite `uapi` crate. These can appear in the label slot when a
///   userland server forwards a kernel-level invocation failure to its
///   client (e.g., mmsrv passing through an underlying retype error).
/// - **Shared personality wire errors** — `TRONA_*`, defined by
///   `crate::protocol`. Userland servers (VFS, netsrv, dnssrv) generate
///   these for personality-level conditions that the kernel ABI does
///   not name (network, DNS, server-died, stale handle, etc.).
/// - **VFS public replies** — `VFS_PUBLIC_REPLY_*`, defined by
///   `trona_protocol::vfs::public`. VFS owns these labels so POSIX,
///   Win32, and future personalities can share the same backend error
///   vocabulary without copying constants into each client.
pub(crate) fn trona_err_to_posix(label: u64) -> i32 {
    use trona_protocol::vfs::public::*;

    match label {
        // Kernel ABI namespace.
        x if x == uapi::KERNITE_OK as u64 => 0,
        x if x == uapi::KERNITE_ERR_NOT_FOUND as u64 => -2, // ENOENT
        x if x == uapi::KERNITE_ERR_ALREADY_EXISTS as u64 => -17, // EEXIST
        x if x == uapi::KERNITE_ERR_SLOT_OCCUPIED as u64 => -17, // EEXIST
        x if x == uapi::KERNITE_ERR_ALREADY_MAPPED as u64 => -17, // EEXIST
        x if x == uapi::KERNITE_ERR_INVALID_ARGUMENT as u64 => -22, // EINVAL
        x if x == uapi::KERNITE_ERR_OUT_OF_MEMORY as u64 => -12, // ENOMEM
        x if x == uapi::KERNITE_ERR_BUSY as u64 => -16,     // EBUSY
        x if x == uapi::KERNITE_ERR_WOULD_BLOCK as u64 => -11, // EAGAIN
        x if x == uapi::KERNITE_ERR_BAD_ADDRESS as u64 => -14, // EFAULT
        x if x == uapi::KERNITE_ERR_INSUFFICIENT_RIGHTS as u64 => -13, // EACCES
        x if x == uapi::KERNITE_ERR_INVALID_CAPABILITY as u64 => -9, // EBADF
        x if x == uapi::KERNITE_ERR_INTERRUPTED as u64 => -4, // EINTR
        x if x == uapi::KERNITE_ERR_DEADLOCK as u64 => -35, // EDEADLK
        x if x == uapi::KERNITE_ERR_INVALID_OPERATION as u64 => -1, // EPERM
        x if x == uapi::KERNITE_ERR_OUT_OF_RANGE as u64 => -34, // ERANGE
        x if x == uapi::KERNITE_ERR_CANCELLED as u64 => -125, // ECANCELED
        x if x == uapi::KERNITE_ERR_TIMED_OUT as u64 => -110, // ETIMEDOUT

        // Personality wire-error namespace.
        TRONA_INVALID_CAPABILITY => -9,   // EBADF
        TRONA_INVALID_OPERATION => -1,    // EPERM
        TRONA_PERMISSION_DENIED => -13,   // EACCES
        TRONA_INVALID_ARGUMENT => -22,    // EINVAL
        TRONA_OUT_OF_MEMORY => -12,       // ENOMEM
        TRONA_NOT_FOUND => -2,            // ENOENT
        TRONA_BUSY => -16,                // EBUSY
        TRONA_ALREADY_EXISTS => -17,      // EEXIST
        TRONA_WOULD_BLOCK => -11,         // EAGAIN
        TRONA_BAD_ADDRESS => -14,         // EFAULT
        TRONA_OUT_OF_RANGE => -34,        // ERANGE
        TRONA_CANCELLED => -125,          // ECANCELED
        TRONA_DEADLOCK => -35,            // EDEADLK
        TRONA_TIMED_OUT => -110,          // ETIMEDOUT
        TRONA_TOO_LARGE => -7,            // E2BIG
        TRONA_NOT_SUPPORTED => -95,       // EOPNOTSUPP
        TRONA_READONLY => -30,            // EROFS
        TRONA_IO_ERROR => -5,             // EIO
        TRONA_ALREADY_BOUND => -16,       // EBUSY
        TRONA_IN_PROGRESS => -115,        // EINPROGRESS
        TRONA_CONN_REFUSED => -111,       // ECONNREFUSED
        TRONA_PROTO_NOT_SUPPORTED => -93, // EPROTONOSUPPORT
        TRONA_HOST_UNREACHABLE => -113,   // EHOSTUNREACH
        TRONA_NET_UNREACHABLE => -101,    // ENETUNREACH
        TRONA_NO_BUFS => -105,            // ENOBUFS
        TRONA_CONN_RESET => -104,         // ECONNRESET
        TRONA_NOT_CONNECTED => -107,      // ENOTCONN
        TRONA_IS_CONNECTED => -106,       // EISCONN
        TRONA_ADDR_IN_USE => -98,         // EADDRINUSE
        TRONA_DNS_NXDOMAIN => -2,         // ENOENT
        TRONA_DNS_SERVER_FAIL => -5,      // EIO
        TRONA_CROSS_DEVICE => -18,        // EXDEV
        TRONA_STALE => -116,              // ESTALE
        TRONA_NO_SPACE => -28,            // ENOSPC
        TRONA_SERVER_DIED => -107,        // ENOTCONN (peer permanently gone)

        // VFS public-reply namespace.
        VFS_PUBLIC_REPLY_OK => 0,
        VFS_PUBLIC_REPLY_BAD_F => -9,               // EBADF
        VFS_PUBLIC_REPLY_NOT_FOUND => -2,           // ENOENT
        VFS_PUBLIC_REPLY_PERM => -13,               // EACCES
        VFS_PUBLIC_REPLY_BUSY => -16,               // EBUSY
        VFS_PUBLIC_REPLY_IO_ERROR => -5,            // EIO
        VFS_PUBLIC_REPLY_INVALID => -22,            // EINVAL
        VFS_PUBLIC_REPLY_NO_MEM => -12,             // ENOMEM
        VFS_PUBLIC_REPLY_LOOP => -40,               // ELOOP
        VFS_PUBLIC_REPLY_NAME_TOO_LONG => -36,      // ENAMETOOLONG
        VFS_PUBLIC_REPLY_NOT_DIR => -20,            // ENOTDIR
        VFS_PUBLIC_REPLY_IS_DIR => -21,             // EISDIR
        VFS_PUBLIC_REPLY_NOT_EMPTY => -39,          // ENOTEMPTY
        VFS_PUBLIC_REPLY_X_DEV => -18,              // EXDEV
        VFS_PUBLIC_REPLY_RO_FS => -30,              // EROFS
        VFS_PUBLIC_REPLY_NOT_SUPPORTED => -95,      // EOPNOTSUPP
        VFS_PUBLIC_REPLY_AGAIN => -11,              // EAGAIN
        VFS_PUBLIC_REPLY_INTR => -4,                // EINTR
        VFS_PUBLIC_REPLY_TIMED_OUT => -110,         // ETIMEDOUT
        VFS_PUBLIC_REPLY_QUOTA => -122,             // EDQUOT
        VFS_PUBLIC_REPLY_EXIST => -17,              // EEXIST
        VFS_PUBLIC_REPLY_SESSION_TORN_DOWN => -107, // ENOTCONN
        VFS_PUBLIC_REPLY_PREDECESSOR_FAILED => -5,  // EIO
        VFS_PUBLIC_REPLY_STALE_INCARNATION => -116, // ESTALE
        VFS_PUBLIC_REPLY_NOT_TTY => -25,            // ENOTTY
        VFS_PUBLIC_REPLY_RANGE => -34,              // ERANGE

        _ => -5, // EIO (generic)
    }
}

#[inline]
pub(crate) fn call_err_to_posix(err: i32) -> i32 {
    trona_err_to_posix(err as u64)
}

#[inline]
pub(crate) fn call_err_to_posix_i64(err: i32) -> i64 {
    call_err_to_posix(err) as i64
}

/// Pack a null-terminated path into message registers starting at `offset`.
pub(crate) unsafe fn pack_path(
    msg: *mut trona_kernel::core_types::TronaMsg,
    offset: usize,
    path: *const u8,
    max_len: usize,
) -> u8 {
    unsafe {
        let avail = (20usize.saturating_sub(offset + 1)) * 8;
        let cap = if max_len < 128 { max_len } else { 128 };
        let limit = if cap < avail { cap } else { avail };
        let mut path_len: u8 = 0;
        while (path_len as usize) < limit && *path.add(path_len as usize) != 0 {
            path_len += 1;
        }
        (*msg).regs[offset] = path_len as u64;
        for i in (offset + 1)..20 {
            (*msg).regs[i] = 0;
        }
        let dst = &mut (*msg).regs[offset + 1] as *mut u64 as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path.add(i);
        }
        path_len
    }
}

// ---------------------------------------------------------------------------
// Signal global state
// ---------------------------------------------------------------------------

// NSIG is already in scope from `pub use crate::consts::*;` above.

/// Per-signal handler function pointers (indexed by signal number).
/// `SIG_DFL` (0) and `SIG_IGN` (1) are special sentinel values.
#[unsafe(no_mangle)]
pub static __sig_handlers: [::core::sync::atomic::AtomicUsize; NSIG] =
    [const { ::core::sync::atomic::AtomicUsize::new(0) }; NSIG];

/// Atomic flag: 1 once signal infrastructure has been initialized.
#[unsafe(no_mangle)]
pub static __sig_initialized: ::core::sync::atomic::AtomicI32 =
    ::core::sync::atomic::AtomicI32::new(0);

/// Per-process pending-signal bitmask. Bit `N` set ⇒ signal `N` has
/// been delivered by init via the signal `MessagePipe` and not yet
/// dispatched. The wakeup-EQ Watch on `signal_pipe.STATE_READABLE`
/// drives `wakeup::drain_signal_pipe()` which OR-folds incoming
/// signal numbers into this word; `posix_sigcheck` swaps the word to
/// 0 to consume them in a single atomic operation.
#[unsafe(no_mangle)]
pub static __sig_pending_bits: ::core::sync::atomic::AtomicU64 =
    ::core::sync::atomic::AtomicU64::new(0);

/// Bitmask of currently blocked signals (bit N = signal N blocked).
#[unsafe(no_mangle)]
pub static mut __sig_blocked_mask: u32 = 0;

/// Per-signal sa_mask: additional signals to block during handler execution.
#[unsafe(no_mangle)]
pub static mut __sig_sa_mask: [u32; NSIG] = [0; NSIG];

/// Per-signal sa_flags (e.g. `SA_RESETHAND`, `SA_RESTART`).
#[unsafe(no_mangle)]
pub static mut __sig_sa_flags: [i32; NSIG] = [0; NSIG];

/// Set by `signals::dispatch_pending_bits` after delivering signals
/// from the wakeup-EQ drain in `posix_sigcheck` (or from a sleep
/// loop's signal-record dispatch). `true` iff every dispatched
/// signal had `SA_RESTART` set — POSIX wrappers test this to decide
/// whether to retry after EINTR.
#[unsafe(no_mangle)]
pub static mut __sig_last_restart: bool = false;

// ---------------------------------------------------------------------------
// C ABI exports: Fork helper (called from fork.S)
// ---------------------------------------------------------------------------

/// Fork implementation called from the `fork.S` assembly trampoline.
///
/// `saved_rsp` points to a stack frame containing callee-saved registers
/// (r15, r14, r13, r12, rbx, rbp, return RIP) saved by the assembly stub.
/// When userland SSE2 is enabled, a 256-byte XMM0-15 save block lives below
/// `saved_rsp` and is restored by the parent return path and `fork_child_entry`.
/// These are packed into an IPC message to init so it can configure the
/// child thread's register state. Returns the child PID (>0) in the parent,
/// or -1 on failure. The child resumes at `child_entry` (never returns here).
#[unsafe(no_mangle)]
pub extern "C" fn _posix_fork_impl(saved_rsp: u64, child_entry: u64) -> i32 {
    use trona_kernel::core_types::TronaMsg;
    use trona_protocol::posix::INIT_FORK;

    if saved_rsp == 0 || child_entry == 0 {
        trona_runtime::debug::serial::serial_puts(b"[FORK_IMPL] invalid args, returning -1\n");
        return -1;
    }

    unsafe {
        let saved = saved_rsp as *const u64;

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        let fork_txid = NEXT_FORK_TXID.fetch_add(1, Ordering::Relaxed);
        msg.label = INIT_FORK;
        msg.regs[0] = saved_rsp;
        msg.regs[1] = child_entry;

        #[cfg(target_arch = "x86_64")]
        {
            msg.length = 9;
            msg.regs[2] = *saved.add(5); // rbp
            msg.regs[3] = *saved.add(4); // rbx
            msg.regs[4] = *saved.add(3); // r12
            msg.regs[5] = *saved.add(2); // r13
            msg.regs[6] = *saved.add(1); // r14
            msg.regs[7] = *saved.add(0); // r15
            msg.regs[8] = *saved.add(6); // return RIP
        }
        #[cfg(target_arch = "aarch64")]
        {
            msg.length = 9;
            msg.regs[2] = *saved.add(18); // x29 (FP)
            msg.regs[3] = *saved.add(19); // x30 (LR / return address)
            msg.regs[4] = *saved.add(8); // x19
            msg.regs[5] = *saved.add(9); // x20
            msg.regs[6] = *saved.add(10); // x21
            msg.regs[7] = *saved.add(11); // x22
            msg.regs[8] = *saved.add(19); // x30 (return address)
        }

        // Pass parent's TLS base so init can set FS_BASE on the child TCB.
        let tls_base: u64 = match tls::current_tls() {
            Some(ptr) => ptr as u64,
            None => 0,
        };
        msg.regs[9] = tls_base;
        msg.regs[10] = fork_txid;
        msg.length = 11;

        // Single blocking MP_CALL — no re-send loop. Re-sending a fork request
        // under the kernel's register-at-send reply-wait would issue a duplicate
        // fork; the kernel re-waits internally and owns resume.
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
            trona_runtime::debug::serial::serial_puts(
                b"[FORK_IMPL] err/non-OK label, returning -1\n",
            );
            return -1;
        }
        reply.regs[0] as i32
    }
}

// ---------------------------------------------------------------------------
// C ABI exports: Socket operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_socket(domain: i32, sock_type: i32, protocol: i32) -> i32 {
    unsafe { socket::posix_socket(domain, sock_type, protocol) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_bind(fd: i32, path: *const u8, addr_len: u32) -> i32 {
    unsafe { socket::posix_bind(fd, path, addr_len) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_listen(fd: i32, backlog: i32) -> i32 {
    unsafe { socket::posix_listen(fd, backlog) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_accept(fd: i32) -> i32 {
    unsafe { socket::posix_accept(fd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_connect(fd: i32, path: *const u8, addr_len: u32) -> i32 {
    unsafe { socket::posix_connect(fd, path, addr_len) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_shutdown(fd: i32, how: i32) -> i32 {
    unsafe { socket::posix_shutdown(fd, how) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_socketpair(
    domain: i32,
    sock_type: i32,
    protocol: i32,
    fds: *mut i32,
) -> i32 {
    unsafe { socket::posix_socketpair(domain, sock_type, protocol, fds) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_posix_poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i32 {
    unsafe { poll::posix_poll(fds, nfds, timeout) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_shm_open(name: *const u8, flags: i32, mode: u32) -> i32 {
    unsafe { misc::posix_shm_open(name, flags, mode) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_shm_unlink(name: *const u8) -> i32 {
    unsafe { misc::posix_shm_unlink(name) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_ftruncate(fd: i32, length: u64) -> i32 {
    unsafe { file::posix_ftruncate(fd, length) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_fsync(fd: i32) -> i32 {
    unsafe { file::posix_fsync(fd) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Pipe / dup
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_pipe(fds: *mut i32) -> i32 {
    unsafe { pipe::posix_pipe(fds) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_pipe2(fds: *mut i32, flags: i32) -> i32 {
    unsafe { pipe::posix_pipe2(fds, flags) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_dup(oldfd: i32) -> i32 {
    unsafe { pipe::posix_dup(oldfd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_dup2(oldfd: i32, newfd: i32) -> i32 {
    unsafe { pipe::posix_dup2(oldfd, newfd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_dup3(oldfd: i32, newfd: i32, flags: i32) -> i32 {
    unsafe { pipe::posix_dup3(oldfd, newfd, flags) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_mkfifo(path: *const u8, mode: u32) -> i32 {
    unsafe { pipe::posix_mkfifo(path, mode) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_mknod(path: *const u8, mode: u32, dev: u64) -> i32 {
    unsafe { at::posix_mknodat(consts::AT_FDCWD, path, mode, dev) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Process groups and UID/GID
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_setpgid(pid: i32, pgid: i32) -> i32 {
    unsafe { proc::posix_setpgid(pid, pgid) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getpgid(pid: i32) -> i32 {
    unsafe { proc::posix_getpgid(pid) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_setsid() -> i32 {
    unsafe { proc::posix_setsid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getsid(pid: i32) -> i32 {
    unsafe { proc::posix_getsid(pid) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getuid() -> i32 {
    unsafe { proc::posix_getuid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_geteuid() -> i32 {
    unsafe { proc::posix_geteuid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getgid() -> i32 {
    unsafe { proc::posix_getgid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getegid() -> i32 {
    unsafe { proc::posix_getegid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getgroups(size: i32, list: *mut i32) -> i32 {
    unsafe { proc::posix_getgroups(size, list) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Time API
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_clock_gettime(clock_id: i32, ts: *mut crate::types::Timespec) -> i32 {
    unsafe { proc::posix_clock_gettime(clock_id, ts) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_gettimeofday(tv: *mut crate::types::Timeval) -> i32 {
    unsafe { proc::posix_gettimeofday(tv) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_nanosleep(
    req: *const crate::types::Timespec,
    rem: *mut crate::types::Timespec,
) -> i32 {
    unsafe { proc::posix_nanosleep(req, rem) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_usleep(usec: u64) -> i32 {
    unsafe { proc::posix_usleep(usec) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_sleep(seconds: u64) -> u64 {
    unsafe { proc::posix_sleep(seconds) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Terminal I/O / fcntl / ioctl / chdir / getcwd
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcgetattr(fd: i32, termios_p: *mut Termios) -> i32 {
    unsafe { misc::posix_tcgetattr(fd, termios_p) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcsetattr(fd: i32, action: i32, termios_p: *const Termios) -> i32 {
    unsafe { misc::posix_tcsetattr(fd, action, termios_p) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_epoll_create1(flags: i32) -> i32 {
    let _ = flags;
    unsafe { poll::posix_epoll_create() }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_epoll_ctl(epfd: i32, op: i32, fd: i32, event: *const EpollEvent) -> i32 {
    unsafe {
        let (events, data) = if !event.is_null() {
            ((*event).events, (*event).data)
        } else {
            (0, 0)
        };
        poll::posix_epoll_ctl(epfd, op, fd, events, data)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_epoll_wait(
    epfd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout: i32,
) -> i32 {
    unsafe { poll::posix_epoll_wait(epfd, events, maxevents, timeout) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_fcntl(fd: i32, cmd: i32, arg: i64) -> i32 {
    unsafe { misc::posix_fcntl(fd, cmd, arg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_isatty(fd: i32) -> i32 {
    unsafe { misc::posix_isatty(fd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_ioctl(fd: i32, request: u64, arg: u64) -> i32 {
    unsafe { misc::posix_ioctl(fd, request, arg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_chdir(path: *const u8) -> i32 {
    unsafe { misc::posix_chdir(path) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getcwd(buf: *mut u8, size: u64) -> i32 {
    unsafe { misc::posix_getcwd(buf, size) }
}

// ---------------------------------------------------------------------------
// C ABI exports: pthread operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_pthread_create(
    thread_out: *mut pthread::PthreadT,
    start_fn: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> i32 {
    unsafe { pthread::pthread_create(thread_out, ::core::ptr::null(), start_fn, arg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_pthread_join(thread: pthread::PthreadT, retval: *mut *mut u8) -> i32 {
    unsafe { pthread::pthread_join(thread, retval) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_pthread_exit(retval: *mut u8) -> ! {
    unsafe { pthread::pthread_exit(retval) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_pthread_self() -> pthread::PthreadT {
    pthread::pthread_self()
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_pthread_detach(thread: pthread::PthreadT) -> i32 {
    unsafe { pthread::pthread_detach(thread) }
}

// ---------------------------------------------------------------------------
// C ABI exports: TLS initialization
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_init_tls() {
    unsafe { tls::init_main_thread_tls() }
}

// ---------------------------------------------------------------------------
// C ABI exports: DNS operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_dns_resolve(hostname: *const u8, hostname_len: usize) -> u32 {
    if hostname.is_null() || hostname_len == 0 || hostname_len > 120 {
        return 0;
    }
    let slice = unsafe { ::core::slice::from_raw_parts(hostname, hostname_len) };
    unsafe { dns::dns_resolve(slice) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getaddrinfo(node: *const u8, result: *mut DnsAddrInfo) -> i32 {
    unsafe { dns::posix_getaddrinfo(node, result) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_dns_resolve_multi(
    hostname: *const u8,
    hostname_len: usize,
    result: *mut DnsResult,
) -> i32 {
    if hostname.is_null() || hostname_len == 0 || hostname_len > 120 || result.is_null() {
        return -1;
    }
    let slice = unsafe { ::core::slice::from_raw_parts(hostname, hostname_len) };
    let r = unsafe { dns::dns_resolve_multi(slice) };
    unsafe {
        *result = r;
    }
    if r.count == 0 { -1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_gethostbyname(name: *const u8) -> u32 {
    unsafe { dns::posix_gethostbyname(name) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_dns_reverse_lookup(
    ip: u32,
    hostname_out: *mut u8,
    hostname_max: usize,
) -> usize {
    unsafe { dns::dns_reverse_lookup(ip, hostname_out, hostname_max) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_dns_cache_flush() {
    unsafe { dns::dns_cache_flush() }
}
