//! trona_posix -- POSIX compatibility layer for SaltyOS
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! This crate provides POSIX-compatible wrappers built on top of the `trona`
//! substrate (kernel ABI, IPC, capability invocations). Every POSIX operation
//! is implemented as an IPC `Call` to a userspace server (VFS, procmgr, mmsrv).
//!
//! # Modules
//!
//! - **`file`** -- File I/O (open, read, write, stat, lseek, etc.)
//! - **`socket`** -- Sockets (socket, bind, listen, accept, connect, etc.)
//! - **`proc`** -- Process management (exec, waitpid, exit, etc.)
//! - **`pipe`** -- Pipes (pipe, pipe2)
//! - **`poll`** -- Polling (poll, epoll, select)
//! - **`mm`** -- Memory management (mmap, munmap, shm)
//! - **`signals`** -- POSIX signal delivery via notifications
//! - **`pthread`** -- POSIX threads (create, join, exit, detach, mutex, key)
//! - **`sync`** -- Synchronization primitives (Mutex, RWLock, Semaphore, Condvar)
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
#![feature(linkage)]

extern crate trona;

pub mod file;
pub mod socket;
pub mod poll;
pub mod pipe;
pub mod proc;
pub mod misc;
pub mod at;
pub(crate) mod bulk;
pub mod mm;
pub mod dns;
pub mod signals;
pub mod pthread;
pub mod sync;
pub mod tls;

pub use file::*;
pub use socket::*;
pub use poll::*;
pub use pipe::*;
pub use proc::*;
pub use misc::*;
pub use at::*;

pub use trona::consts::*;
pub use trona::types::*;

// Standard child CSpace layout (set by procmgr at spawn time)
const CAP_PROCMGR_EP: u64 = 3;
const CAP_VFS_EP: u64 = 4;

/// Convert a server error label to a negative POSIX errno code.
pub(crate) fn trona_err_to_posix(label: u64) -> i32 {
    match label {
        TRONA_OK => 0,
        TRONA_NOT_FOUND => -2,                // ENOENT
        TRONA_ALREADY_EXISTS => -17,           // EEXIST
        TRONA_INVALID_ARGUMENT => -22,         // EINVAL
        TRONA_OUT_OF_MEMORY => -12,            // ENOMEM
        TRONA_BUSY => -16,                     // EBUSY
        TRONA_WOULD_BLOCK => -11,              // EAGAIN
        TRONA_IN_PROGRESS => -115,            // EINPROGRESS
        TRONA_BAD_ADDRESS => -14,              // EFAULT
        TRONA_INSUFFICIENT_RIGHTS => -13,      // EACCES
        TRONA_INVALID_CAPABILITY => -9,        // EBADF
        TRONA_INTERRUPTED => -4,               // EINTR
        TRONA_DEADLOCK => -35,                 // EDEADLK
        TRONA_INVALID_OPERATION => -1,         // EPERM
        TRONA_OUT_OF_RANGE => -34,             // ERANGE
        TRONA_CANCELLED => -125,               // ECANCELED
        TRONA_CONN_REFUSED => -111,            // ECONNREFUSED
        TRONA_TIMED_OUT => -110,               // ETIMEDOUT
        TRONA_PROTO_NOT_SUPPORTED => -93,      // EPROTONOSUPPORT
        TRONA_HOST_UNREACHABLE => -113,        // EHOSTUNREACH
        TRONA_NET_UNREACHABLE => -101,         // ENETUNREACH
        TRONA_NO_BUFS => -105,                 // ENOBUFS
        TRONA_CONN_RESET => -104,              // ECONNRESET
        TRONA_NOT_CONNECTED => -107,           // ENOTCONN
        TRONA_IS_CONNECTED => -106,            // EISCONN
        TRONA_ADDR_IN_USE => -98,              // EADDRINUSE
        TRONA_DNS_NXDOMAIN => -2,              // ENOENT
        TRONA_DNS_SERVER_FAIL => -5,           // EIO
        _ => -5,                               // EIO (generic)
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

/// IPC call with retry only when the server never received the request.
///
/// Retries on `TRONA_RESTART` (CallSendBlocked interruption — server
/// never saw the message, safe to re-send). Returns `TRONA_INTERRUPTED`
/// as-is (ReplyWait interruption — server already processed the request,
/// re-sending may cause duplicates for non-idempotent operations).
///
/// Use for non-idempotent operations: open, close, pipe, dup, socket,
/// bind, mkdir, unlink, rename, etc.
pub(crate) unsafe fn ipc_call_retry(
    ep: u64,
    msg: *const trona::types::TronaMsg,
    reply: *mut trona::types::TronaMsg,
) -> i32 {
    unsafe {
        loop {
            let err = trona::ipc::call_ctx(
                crate::tls::current_ipc_ctx(),
                ep,
                msg,
                reply,
            );
            if err == trona::consts::TRONA_RESTART as i32 {
                continue;
            }
            return err;
        }
    }
}

/// IPC call with retry on any signal interruption.
///
/// Retries on both `TRONA_RESTART` (CallSendBlocked) and
/// `TRONA_INTERRUPTED` (ReplyWait). Safe only for idempotent read-only
/// operations where re-sending has no side effects: stat, fstat, getpid,
/// getuid, getcwd, access, lseek, etc.
pub(crate) unsafe fn ipc_call_retry_idempotent(
    ep: u64,
    msg: *const trona::types::TronaMsg,
    reply: *mut trona::types::TronaMsg,
) -> i32 {
    unsafe {
        loop {
            let err = trona::ipc::call_ctx(
                crate::tls::current_ipc_ctx(),
                ep,
                msg,
                reply,
            );
            if err == trona::consts::TRONA_RESTART as i32
                || err == trona::consts::TRONA_INTERRUPTED as i32
            {
                continue;
            }
            return err;
        }
    }
}

/// Pack a null-terminated path into message registers starting at `offset`.
pub(crate) unsafe fn pack_path(msg: *mut TronaMsg, offset: usize, path: *const u8, max_len: usize) -> u8 {
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

use trona::consts::NSIG;

/// Per-signal handler function pointers (indexed by signal number).
/// `SIG_DFL` (0) and `SIG_IGN` (1) are special sentinel values.
#[unsafe(no_mangle)]
pub static __sig_handlers: [core::sync::atomic::AtomicUsize; NSIG] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; NSIG];

/// Atomic flag: 1 once signal infrastructure has been initialized.
#[unsafe(no_mangle)]
pub static __sig_initialized: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

/// Bitmask of currently blocked signals (bit N = signal N blocked).
#[unsafe(no_mangle)]
pub static mut __sig_blocked_mask: u32 = 0;

/// Per-signal sa_mask: additional signals to block during handler execution.
#[unsafe(no_mangle)]
pub static mut __sig_sa_mask: [u32; NSIG] = [0; NSIG];

/// Per-signal sa_flags (e.g. `SA_RESETHAND`, `SA_RESTART`).
#[unsafe(no_mangle)]
pub static mut __sig_sa_flags: [i32; NSIG] = [0; NSIG];

/// Set by `__signal_dispatcher` after delivering signals.
/// `true` if ALL delivered signals had SA_RESTART set.
/// POSIX wrappers check this to decide whether to retry after EINTR.
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
/// These are packed into an IPC message to procmgr so it can configure the
/// child thread's register state. Returns the child PID (>0) in the parent,
/// or -1 on failure. The child resumes at `child_entry` (never returns here).
#[unsafe(no_mangle)]
pub extern "C" fn _posix_fork_impl(saved_rsp: u64, child_entry: u64) -> i32 {
    use trona::consts::*;
    use trona::types::*;

    if saved_rsp == 0 || child_entry == 0 {
        return -1;
    }

    unsafe {
        let saved = saved_rsp as *const u64;

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = POSIX_PM_FORK;
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
            msg.regs[4] = *saved.add(8);  // x19
            msg.regs[5] = *saved.add(9);  // x20
            msg.regs[6] = *saved.add(10); // x21
            msg.regs[7] = *saved.add(11); // x22
            msg.regs[8] = *saved.add(19); // x30 (return address)
        }

        // Pass parent's TLS base so procmgr can set FS_BASE on the child TCB.
        let tls_base: u64 = match tls::current_tls() {
            Some(ptr) => ptr as u64,
            None => 0,
        };
        msg.regs[9] = tls_base;
        msg.length = 10;

        let err = crate::ipc_call_retry(
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
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
pub extern "C" fn trona_socketpair(fds: *mut i32) -> i32 {
    unsafe { socket::posix_socketpair(fds) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_posix_poll(fds: *mut trona::types::PollFd, nfds: u32, timeout: i32) -> i32 {
    unsafe { poll::posix_poll(fds, nfds, timeout) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_shm_open(name: *const u8, flags: i32) -> i32 {
    unsafe { misc::posix_shm_open(name, flags) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_shm_unlink(name: *const u8) -> i32 {
    unsafe { misc::posix_shm_unlink(name) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_ftruncate(fd: i32, length: u64) -> i32 {
    unsafe { file::posix_ftruncate(fd, length) }
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
pub extern "C" fn trona_clock_gettime(clock_id: i32, ts: *mut trona::types::Timespec) -> i32 {
    unsafe { proc::posix_clock_gettime(clock_id, ts) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_gettimeofday(tv: *mut trona::types::Timeval) -> i32 {
    unsafe { proc::posix_gettimeofday(tv) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_nanosleep(req: *const trona::types::Timespec, rem: *mut trona::types::Timespec) -> i32 {
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
pub extern "C" fn trona_tcgetattr(fd: i32, termios_p: *mut trona::types::Termios) -> i32 {
    unsafe { misc::posix_tcgetattr(fd, termios_p) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcsetattr(fd: i32, action: i32, termios_p: *const trona::types::Termios) -> i32 {
    unsafe { misc::posix_tcsetattr(fd, action, termios_p) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_epoll_create1(flags: i32) -> i32 {
    let _ = flags;
    unsafe { poll::posix_epoll_create() }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_epoll_ctl(
    epfd: i32,
    op: i32,
    fd: i32,
    event: *const trona::types::EpollEvent,
) -> i32 {
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
    events: *mut trona::types::EpollEvent,
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
    unsafe { pthread::pthread_create(thread_out, core::ptr::null(), start_fn, arg) }
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
    let slice = unsafe { core::slice::from_raw_parts(hostname, hostname_len) };
    unsafe { dns::dns_resolve(slice) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_getaddrinfo(node: *const u8, result: *mut trona::types::DnsAddrInfo) -> i32 {
    unsafe { dns::posix_getaddrinfo(node, result) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_dns_resolve_multi(
    hostname: *const u8,
    hostname_len: usize,
    result: *mut trona::types::DnsResult,
) -> i32 {
    if hostname.is_null() || hostname_len == 0 || hostname_len > 120 || result.is_null() {
        return -1;
    }
    let slice = unsafe { core::slice::from_raw_parts(hostname, hostname_len) };
    let r = unsafe { dns::dns_resolve_multi(slice) };
    unsafe { *result = r; }
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
