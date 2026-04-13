// POSIX constants: file flags, signals, sockets, poll, mmap, device types.
// SPDX-License-Identifier: GPL-2.0-only

// O_* flags (POSIX: int -> u32)
pub const O_RDONLY: u32 = 0x0000;
pub const O_WRONLY: u32 = 0x0001;
pub const O_RDWR: u32 = 0x0002;
pub const O_ACCMODE: u32 = 0x0003;
pub const O_CREAT: u32 = 0x0040;
pub const O_EXCL: u32 = 0x0080;
pub const O_NOCTTY: u32 = 0x0100;
pub const O_TRUNC: u32 = 0x0200;
pub const O_APPEND: u32 = 0x0400;
pub const O_NONBLOCK: u32 = 0x0800;
pub const O_CLOEXEC: u32 = 0x80000;

// SEEK_* constants
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

// File type constants
pub const S_IFMT: u64 = 0o170000;
pub const S_IFDIR: u64 = 0o040000;
pub const S_IFCHR: u64 = 0o020000;
pub const S_IFREG: u64 = 0o100000;
pub const S_IFSOCK: u64 = 0o140000;
pub const S_IFIFO: u64 = 0o010000;
pub const S_IFLNK: u64 = 0o120000;

// Permission bits
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;

pub const S_IRWXU: u32 = 0o700;
pub const S_IRUSR: u32 = 0o400;
pub const S_IWUSR: u32 = 0o200;
pub const S_IXUSR: u32 = 0o100;
pub const S_IRWXG: u32 = 0o070;
pub const S_IRGRP: u32 = 0o040;
pub const S_IWGRP: u32 = 0o020;
pub const S_IXGRP: u32 = 0o010;
pub const S_IRWXO: u32 = 0o007;
pub const S_IROTH: u32 = 0o004;
pub const S_IWOTH: u32 = 0o002;
pub const S_IXOTH: u32 = 0o001;

// Supplementary group limit
pub const NGROUPS_MAX: usize = 32;

// Access mode flags
pub const F_OK: u64 = 0;
pub const R_OK: u64 = 4;
pub const W_OK: u64 = 2;
pub const X_OK: u64 = 1;

// Directory entry types
pub const DT_UNKNOWN: u8 = 0;
pub const DT_REG: u8 = 8;
pub const DT_DIR: u8 = 4;
pub const DT_CHR: u8 = 2;
pub const DT_SOCK: u8 = 12;
pub const DT_FIFO: u8 = 1;
pub const DT_LNK: u8 = 10;

// waitpid options
pub const WNOHANG: u64 = 1;

// Signal numbers
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGABRT: i32 = 6;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const NSIG: usize = 32;

// Signal disposition categories
pub const SIG_DISP_DFL: u64 = 0;
pub const SIG_DISP_IGN: u64 = 1;
pub const SIG_DISP_CATCH: u64 = 2;

// sigaction flags
pub const SA_RESETHAND: i32 = 0x80000000u32 as i32;
pub const SA_RESTART: i32 = 0x10000000;

// PROT_* flags
pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;

// MAP_* flags
pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANONYMOUS: i32 = 0x20;
pub const MAP_LAZY: i32 = 0x40;

// Socket constants
pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const SOCK_RAW: i32 = 3;
pub const IPPROTO_ICMP: i32 = 1;
pub const IPPROTO_IP: i32 = 0;
pub const SCM_RIGHTS: i32 = 1;
pub const SCM_TIMESTAMP: i32 = 2;
pub const SOL_SOCKET: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_BROADCAST: i32 = 6;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_TIMESTAMP: i32 = 0x0000_0400;
pub const SO_PROTOCOL: i32 = 38;
pub const SO_DOMAIN: i32 = 39;
pub const SO_TS_CLOCK: i32 = 0x1017;
pub const SO_TS_MONOTONIC: i32 = 3;
pub const IP_TTL: i32 = 2;
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

// AT_* flags for *at() family
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
pub const AT_REMOVEDIR: i32 = 0x200;
pub const AT_SYMLINK_FOLLOW: i32 = 0x400;
pub const AT_EMPTY_PATH: i32 = 0x1000;

// utimensat special values
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

// fcntl commands
pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const F_DUPFD_CLOEXEC: i32 = 1030;
pub const FD_CLOEXEC: i32 = 1;

// ioctl requests
pub const TIOCGPGRP: u64 = 0x540F;
pub const TIOCSPGRP: u64 = 0x5410;
pub const TIOCSCTTY: u64 = 0x540E;
pub const TIOCGWINSZ: u64 = 0x5413;
pub const TIOCSWINSZ: u64 = 0x5414;
pub const TIOCNOTTY: u64 = 0x5422;
pub const TIOCGSID: u64 = 0x5429;
pub const TIOCGPTN: u64 = 0x80045430;

// Framebuffer ioctl requests
pub const FBIOGET_VSCREENINFO: u64 = 0x4600;
pub const FBIOGET_FSCREENINFO: u64 = 0x4602;

/// Poll event flags.
pub const POLLIN: i16 = 0x001;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;
pub const POLLNVAL: i16 = 0x020;

/// Epoll constants.
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;

/// Default search PATH for program execution.
pub const DEFAULT_PATH: &[u8] = b"/bin:/sbin:/usr/bin:/usr/sbin";
pub const DEFAULT_PATH_NUL: &[u8] = b"/bin:/sbin:/usr/bin:/usr/sbin\0";

/// VFS device type constants.
pub const DEV_CONSOLE: u8 = 0;
pub const DEV_NULL: u8 = 1;
pub const DEV_ZERO: u8 = 2;
pub const DEV_FB0: u8 = 3;
pub const DEV_PTY_SLAVE: u8 = 4;
pub const DEV_PTMX: u8 = 5;
pub const DEV_URANDOM: u8 = 6;

/// Synthetic device ids used for terminal identity across procfs and libc.
pub const TTY_DEV_CONSOLE: u64 = 1;
pub const TTY_DEV_PTS_BASE: u64 = 0x1000;

pub const fn tty_dev_for_console() -> u64 {
    TTY_DEV_CONSOLE
}

pub const fn tty_dev_for_pts(pty_id: u64) -> u64 {
    TTY_DEV_PTS_BASE + pty_id
}

// Resource limits
pub const RLIMIT_NOFILE: u32 = 0;
pub const RLIMIT_NPROC: u32 = 1;
pub const RLIMIT_AS: u32 = 2;
pub const RLIMIT_FSIZE: u32 = 3;
pub const RLIMIT_STACK: u32 = 4;
pub const RLIMIT_CPU: u32 = 5;
pub const RLIMIT_CORE: u32 = 6;
pub const RLIMIT_DATA: u32 = 7;
pub const RLIM_NLIMITS: usize = 8;
pub const RLIM_INFINITY: u64 = u64::MAX;
