// POSIX-specific types for SaltyOS userland.
// SPDX-License-Identifier: GPL-2.0-only
//
// Types in this file implement POSIX personality semantics: stat, dirent,
// sockets, poll, termios, signals, epoll, and DNS resolution.

/// POSIX-compatible stat structure returned by `posix_stat` / `posix_fstat`.
/// Fields are packed into IPC message registers by the VFS server.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaStat {
    pub st_ino: u64,
    pub st_mode: u64,
    pub st_nlink: u64,
    pub st_size: u64,
    pub st_uid: u64,
    pub st_gid: u64,
    pub st_mtime: u64,
    pub st_type: u64,
}

impl TronaStat {
    pub const fn zeroed() -> Self {
        TronaStat {
            st_ino: 0,
            st_mode: 0,
            st_nlink: 0,
            st_size: 0,
            st_uid: 0,
            st_gid: 0,
            st_mtime: 0,
            st_type: 0,
        }
    }
}

/// POSIX-compatible directory entry returned by `posix_readdir`.
/// `d_name` is null-terminated, max 127 chars + NUL.
#[repr(C)]
pub struct TronaDirent {
    pub d_ino: u64,
    pub d_type: u8,
    pub d_namlen: u8,
    pub d_name: [u8; 128],
}

impl TronaDirent {
    pub const fn zeroed() -> Self {
        TronaDirent {
            d_ino: 0,
            d_type: 0,
            d_namlen: 0,
            d_name: [0; 128],
        }
    }
}

/// Returns true if the child terminated normally (exit, not signal).
/// POSIX encoding: low 7 bits = termination signal (0 = normal exit).
pub fn wifexited(s: i32) -> bool {
    (s & 0x7f) == 0
}
/// Extract the exit code from a wait status (bits 15:8).
pub fn wexitstatus(s: i32) -> i32 {
    (s >> 8) & 0xff
}
/// Returns true if the child was terminated by a signal.
pub fn wifsignaled(s: i32) -> bool {
    (s & 0x7f) != 0 && (s & 0x7f) != 0x7f
}
/// Extract the signal number that caused termination.
pub fn wtermsig(s: i32) -> i32 {
    s & 0x7f
}
/// Returns true if the child is currently stopped.
pub fn wifstopped(s: i32) -> bool {
    (s & 0xff) == 0x7f
}
/// Extract the signal number that caused the child to stop.
pub fn wstopsig(s: i32) -> i32 {
    (s >> 8) & 0xff
}

// Signal handler type
pub type SigHandlerT = Option<unsafe extern "C" fn(i32)>;

// Special handler values encoded as usize
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

/// Unix domain socket address. `sun_family` is `AF_UNIX` (1).
/// `sun_path` holds the null-terminated filesystem path (max 64 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; 64],
}

impl SockAddrUn {
    pub const fn zeroed() -> Self {
        SockAddrUn {
            sun_family: 0,
            sun_path: [0; 64],
        }
    }
}

/// IPv4 socket address. `family` is `AF_INET` (2).
///
/// `port` and `addr` are in **host byte order** (not network byte order).
/// This is an intentional deviation from the POSIX `sockaddr_in` convention
/// to avoid byte-swapping overhead in a single-architecture OS. All netsrv
/// IPC messages pass these values in host byte order.
///
/// Example: 10.0.2.2 is `0x0A000202`, port 80 is `80` (not `0x5000`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    pub family: u16,
    pub port: u16,
    pub addr: u32,
}

impl SockAddrIn {
    pub const fn zeroed() -> Self {
        SockAddrIn {
            family: 0,
            port: 0,
            addr: 0,
        }
    }
}

/// POSIX poll file descriptor: `fd` to monitor, requested `events`
/// (POLLIN/POLLOUT), and returned `revents` filled by the kernel/VFS.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

impl PollFd {
    pub const fn zeroed() -> Self {
        PollFd {
            fd: -1,
            events: 0,
            revents: 0,
        }
    }
}

/// POSIX termios structure for terminal I/O control. Layout matches `saltyc`.
/// Packed into IPC messages for `tcgetattr`/`tcsetattr` VFS calls.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Termios {
    pub const fn zeroed() -> Self {
        Termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; 32],
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }
}

/// Epoll event structure: `events` is a bitmask (EPOLLIN, EPOLLOUT, etc.),
/// `data` is an opaque user value associated with the fd.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

impl EpollEvent {
    pub const fn zeroed() -> Self {
        EpollEvent {
            events: 0,
            data: 0,
        }
    }
}

/// Maximum number of IP addresses returned by a single DNS query.
pub const DNS_MAX_RESULTS: usize = 4;

/// Multi-result DNS resolution: carries up to `DNS_MAX_RESULTS` IPv4
/// addresses from a single dnssrv query without heap allocation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsResult {
    /// Number of valid entries in `addrs` (0 = resolution failed).
    pub count: u32,
    /// TTL in seconds from the DNS reply.
    pub ttl: u32,
    /// IPv4 addresses in host byte order.
    pub addrs: [u32; DNS_MAX_RESULTS],
}

impl DnsResult {
    pub const fn zeroed() -> Self {
        DnsResult {
            count: 0,
            ttl: 0,
            addrs: [0; DNS_MAX_RESULTS],
        }
    }
}

/// DNS address info result (POSIX getaddrinfo equivalent).
/// Returns a single result per call. No heap-allocated linked list since
/// this is a `no_std` environment; callers resolve one address at a time.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsAddrInfo {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    pub addr: SockAddrIn,
}

impl DnsAddrInfo {
    pub const fn zeroed() -> Self {
        DnsAddrInfo {
            family: 0,
            socktype: 0,
            protocol: 0,
            addr: SockAddrIn::zeroed(),
        }
    }
}
