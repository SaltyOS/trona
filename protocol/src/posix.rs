// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX personality IPC protocol labels.
//!
//! Used between POSIX wrappers in this crate and the userland servers
//! they call (init supervisor, VFS, posix_ttysrv, dnssrv). Non-POSIX
//! subsystems must not depend on these labels — they are personality-
//! private.
//!
//! Numeric values are chosen so the same init / VFS / netsrv / dnssrv /
//! namesrv / mmsrv / rsrcsrv servers dispatch POSIX-personality and
//! substrate-side calls against a single wire layout.

// Generic userland status labels live in `trona_protocol::common`.
// This module contains only POSIX-personality labels and POSIX-only status
// extensions.

pub const TRONA_ALREADY_BOUND: u64 = 100;
pub const TRONA_ADDR_IN_USE: u64 = 101;
pub const TRONA_CONN_REFUSED: u64 = 102;
pub const TRONA_CONN_RESET: u64 = 103;
pub const TRONA_CROSS_DEVICE: u64 = 104;
pub const TRONA_DNS_NXDOMAIN: u64 = 105;
pub const TRONA_DNS_SERVER_FAIL: u64 = 106;
pub const TRONA_HOST_UNREACHABLE: u64 = 107;
pub const TRONA_IN_PROGRESS: u64 = 108;
pub const TRONA_IS_CONNECTED: u64 = 109;
pub const TRONA_NET_UNREACHABLE: u64 = 110;
pub const TRONA_NOT_CONNECTED: u64 = 111;
pub const TRONA_NO_BUFS: u64 = 112;
pub const TRONA_NO_SPACE: u64 = 113;
pub const TRONA_PROTO_NOT_SUPPORTED: u64 = 114;
pub const TRONA_SERVER_DIED: u64 = 115;
pub const TRONA_STALE: u64 = 116;

// Async inet completion operation classes used by netsrv -> VFS callbacks.
pub const INET_OP_CONNECT: u8 = 1;
pub const INET_OP_RECV: u8 = 2;
pub const INET_OP_ACCEPT: u8 = 3;
pub const INET_OP_RECVFROM: u8 = 4;

// ---------------------------------------------------------------------------
// init supervisor (block 0x100..=0x1FF).
//
// POSIX wrappers call init via per-client MP. Sub-class labels (CRED,
// PGRP_SESSION, RLIMIT, ITIMER, THREAD, GET_PROC_INFO, SERVICE_QUERY)
// pack the sub-op into `regs[0]`; sub-op constants live below the
// parent label.
// ---------------------------------------------------------------------------

pub const INIT_GET_ABI_VERSION: u64 = 0x100;
pub const INIT_GET_BOOTINFO_FRAME: u64 = 0x101;
pub const INIT_SPAWN: u64 = 0x102;
pub const INIT_FORK: u64 = 0x103;
pub const INIT_EXEC: u64 = 0x104;
pub const INIT_EXIT: u64 = 0x105;
pub const INIT_GET_PID: u64 = 0x106;
pub const INIT_GET_PPID: u64 = 0x107;
// 0x108 retired (was INIT_FORK_RESULT, a vestigial child self-publish ack with
// no live sender once init owned the fork path); do not reuse.
pub const INIT_REGISTER_INTERFACE: u64 = 0x109;
pub const INIT_RESOLVE_INTERFACE: u64 = 0x10A;
pub const INIT_REAP_BADGE: u64 = 0x10B;
pub const INIT_WAIT: u64 = 0x110;
pub const INIT_KILL: u64 = 0x111;
pub const INIT_KILL_PGID: u64 = 0x112;
pub const INIT_SIGACTION: u64 = 0x113;
pub const INIT_SIGPENDING_DUMP: u64 = 0x114;

// CRED sub-op (regs[0]):
pub const INIT_CRED: u64 = 0x120;
pub const INIT_CRED_SUB_GETUID: u64 = 0x00;
pub const INIT_CRED_SUB_GETGID: u64 = 0x01;
pub const INIT_CRED_SUB_GETEUID: u64 = 0x02;
pub const INIT_CRED_SUB_GETEGID: u64 = 0x03;
pub const INIT_CRED_SUB_GETGROUPS: u64 = 0x04;
pub const INIT_CRED_SUB_SETUID: u64 = 0x05;
pub const INIT_CRED_SUB_SETGID: u64 = 0x06;
pub const INIT_CRED_SUB_SETEUID: u64 = 0x07;
pub const INIT_CRED_SUB_SETEGID: u64 = 0x08;
pub const INIT_CRED_SUB_SETREUID: u64 = 0x09;
pub const INIT_CRED_SUB_SETREGID: u64 = 0x0A;
pub const INIT_CRED_SUB_SETGROUPS: u64 = 0x0B;
pub const INIT_CRED_SUB_GETRESUID: u64 = 0x0C;
pub const INIT_CRED_SUB_GETRESGID: u64 = 0x0D;
pub const INIT_CRED_SUB_SETRESUID: u64 = 0x0E;
pub const INIT_CRED_SUB_SETRESGID: u64 = 0x0F;
pub const INIT_CRED_SUB_UMASK: u64 = 0x10;

// PGRP_SESSION sub-op (regs[0]):
pub const INIT_PGRP_SESSION: u64 = 0x130;
pub const INIT_PGRP_SUB_SETPGID: u64 = 0x00;
pub const INIT_PGRP_SUB_GETPGID: u64 = 0x01;
pub const INIT_PGRP_SUB_GETPGRP: u64 = 0x02;
pub const INIT_PGRP_SUB_SETSID: u64 = 0x03;
pub const INIT_PGRP_SUB_GETSID: u64 = 0x04;
pub const INIT_PGRP_SUB_GETPGID_BY_BADGE: u64 = 0x05;
pub const INIT_PGRP_SUB_GETSID_BY_BADGE: u64 = 0x06;
pub const INIT_PGRP_SUB_GET_SID_PGID_BY_BADGE: u64 = 0x07;

// RLIMIT sub-op (regs[0]):
pub const INIT_RLIMIT: u64 = 0x140;
pub const INIT_RLIMIT_SUB_GET: u64 = 0x00;
pub const INIT_RLIMIT_SUB_SET: u64 = 0x01;

// ITIMER sub-op (regs[0]):
pub const INIT_ITIMER: u64 = 0x141;
pub const INIT_ITIMER_SUB_GET: u64 = 0x00;
pub const INIT_ITIMER_SUB_SET: u64 = 0x01;

// THREAD sub-op (regs[0]):
pub const INIT_THREAD: u64 = 0x150;
pub const INIT_THREAD_SUB_CREATE: u64 = 0x00;
pub const INIT_THREAD_SUB_EXIT: u64 = 0x01;
pub const INIT_THREAD_SUB_JOIN: u64 = 0x02;
pub const INIT_THREAD_SUB_DETACH: u64 = 0x03;
pub const INIT_THREAD_SUB_REAP: u64 = 0x04;
pub const INIT_THREAD_SUB_GET_THREAD_CAPS: u64 = 0x05;

// GET_PROC_INFO sub-op (regs[0]):
pub const INIT_GET_PROC_INFO: u64 = 0x160;
pub const INIT_GET_PROC_INFO_SUB_GET_PROC_INFO: u64 = 0x00;
pub const INIT_GET_PROC_INFO_SUB_LIST_PIDS: u64 = 0x01;
pub const INIT_GET_PROC_INFO_SUB_GET_PROC_TIMES: u64 = 0x02;
pub const INIT_GET_PROC_INFO_SUB_GET_SYSTEM_STATS: u64 = 0x03;
pub const INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC: u64 = 0x04;
pub const INIT_GET_PROC_INFO_SUB_LIST_PIDS_BUF: u64 = 0x05;
pub const INIT_GET_PROC_INFO_SUB_GET_ARGV: u64 = 0x06;
pub const INIT_GET_PROC_INFO_SUB_GET_EXE_PATH: u64 = 0x07;
pub const INIT_GET_PROC_INFO_SUB_DUMP_PENDING: u64 = 0x08;

pub const INIT_SERVICE_QUERY: u64 = 0x161;

pub const INIT_LIFECYCLE_SUBSCRIBE: u64 = 0x170;
pub const INIT_LIFECYCLE_UNSUBSCRIBE: u64 = 0x171;
pub const INIT_REPORT_FAULT: u64 = 0x172;
pub const INIT_REGISTER_FAULT_OBSERVER: u64 = 0x173;
pub const INIT_UNREGISTER_FAULT_OBSERVER: u64 = 0x174;
/// `Type=notify` leaf service readiness signal. Caller invokes this on
/// its init control endpoint to tell the supervisor it is fully
/// initialized. `regs[0] = service_id`, no reply (Send only). Equivalent
/// to systemd `sd_notify(READY=1)` over the init control MP transport.
pub const INIT_NOTIFY_READY: u64 = 0x180;
pub const INIT_DEBUG_DUMP_TABLE: u64 = 0x1F0;

// ---------------------------------------------------------------------------
// VFS server — neutral filesystem operations.
// ---------------------------------------------------------------------------

// All numeric values map onto the VFS public block (0x500..=0x5FF)
// the server hosts at `userland/core/vfs/src/ipc/protocol/public.rs`.
// POSIX-specific personality wrappers (chdir, isatty, getcwd,
// tcgetattr, tcsetattr) keep their distinct labels in the
// 0x5C0..=0x5DF region of the same block — vfs dispatches them
// through `personality::posix` rather than the neutral fileops
// path, but the numeric range stays inside the public block so a
// single wire never sees two disjoint label spaces.

pub use crate::correlation::*;
pub use crate::vfs::backend::*;

pub const VFS_POSIX_OPEN: u64 = 0x500;
pub const VFS_POSIX_STAT: u64 = 0x505;
pub const VFS_POSIX_FSTAT: u64 = 0x506;
pub const VFS_POSIX_FSTATAT: u64 = 0x507;
pub const VFS_POSIX_LSTAT: u64 = 0x508;
pub const VFS_POSIX_FTRUNCATE: u64 = 0x50A;
pub const VFS_FSYNC: u64 = 0x50B;
pub const VFS_POSIX_DUP: u64 = 0x50D;
pub const VFS_POSIX_DUP2: u64 = 0x50E;
pub const VFS_POSIX_DUP3: u64 = 0x50F;
pub const VFS_POSIX_FCNTL: u64 = 0x510;
pub const VFS_POSIX_IOCTL: u64 = 0x511;
pub const VFS_POSIX_OPENAT: u64 = 0x512;
pub const VFS_POSIX_ACCESS: u64 = 0x513;
pub const VFS_POSIX_FACCESSAT: u64 = 0x514;
// `fchmod(fd)` maps to the fd-based `VFS_FCHMOD`; `fchmodat(dirfd, path,
// mode, flags)` maps to the path-based `VFS_CHMOD` (anchor_fd + an
// `AT_SYMLINK_NOFOLLOW` flags word). The fd-vs-path split mirrors the
// server dispatch in vfs `personality/posix/setattr.rs`; the earlier
// literals had the fd and path variants transposed (fchmod hit the path
// handler and fchmodat hit the fd handler), so they are now defined as
// aliases of the canonical labels to keep the mapping correct.
pub const VFS_POSIX_FCHMOD: u64 = crate::vfs::public::VFS_FCHMOD;
pub const VFS_POSIX_FCHMODAT: u64 = crate::vfs::public::VFS_CHMOD;
pub const VFS_POSIX_FCHOWN: u64 = crate::vfs::public::VFS_FCHOWN;
pub const VFS_POSIX_FCHOWNAT: u64 = crate::vfs::public::VFS_CHOWN;
pub const VFS_POSIX_UTIMENSAT: u64 = 0x519;
pub const VFS_POSIX_READLINKAT: u64 = 0x51B;
pub const VFS_POSIX_READDIR: u64 = 0x51C;
pub const VFS_POSIX_OPENDIR: u64 = VFS_POSIX_OPEN;
pub const VFS_POSIX_MKDIR: u64 = 0x51D;
pub const VFS_POSIX_MKDIRAT: u64 = 0x51D;
pub const VFS_POSIX_RMDIR: u64 = 0x51E;
pub const VFS_POSIX_LINKAT: u64 = 0x51F;
pub const VFS_POSIX_UNLINK: u64 = 0x520;
pub const VFS_POSIX_UNLINKAT: u64 = 0x520;
pub const VFS_POSIX_SYMLINKAT: u64 = 0x521;
pub const VFS_POSIX_RENAME: u64 = 0x522;
pub const VFS_POSIX_RENAMEAT: u64 = 0x522;
pub const VFS_MOUNT: u64 = 0x523;
pub const VFS_UMOUNT: u64 = 0x524;
pub const VFS_STATFS: u64 = 0x525;
pub const VFS_FSTATFS: u64 = 0x525;
pub const VFS_POSIX_POLL: u64 = 0x528;
pub const VFS_POSIX_EPOLL_CREATE: u64 = 0x529;
pub const VFS_POSIX_EPOLL_CTL: u64 = 0x52A;
pub const VFS_POSIX_EPOLL_WAIT: u64 = 0x52B;
pub const VFS_POSIX_SHM_OPEN: u64 = 0x52D;
pub const VFS_POSIX_SHM_UNLINK: u64 = 0x52E;
pub const VFS_POSIX_PIPE: u64 = 0x52F;
pub const VFS_POSIX_FIFO_OPEN: u64 = 0x531;
pub const VFS_POSIX_SOCKET: u64 = 0x532;
pub const VFS_POSIX_SOCKPAIR: u64 = 0x533;
pub const VFS_POSIX_BIND: u64 = 0x534;
pub const VFS_POSIX_LISTEN: u64 = 0x535;
pub const VFS_POSIX_ACCEPT: u64 = 0x536;
pub const VFS_POSIX_CONNECT: u64 = 0x537;
pub const VFS_POSIX_SHUTDOWN: u64 = 0x538;
pub const VFS_POSIX_SENDMSG: u64 = 0x539;
pub const VFS_POSIX_RECVMSG: u64 = 0x53A;
// Bulk SHM transfer uses the unified VFS_READ / VFS_WRITE wire with the
// VFS_RW_FLAG_SHM flag (see vfs::public); setup/teardown use
// VFS_REGISTER_BULK_SHM / VFS_RELEASE_BULK_SHM. No dedicated bulk labels.
pub const VFS_PREAD: u64 = 0x502;
pub const VFS_PWRITE: u64 = 0x503;

// POSIX-personality-only labels — POSIX-only extension block at
// `0x5C0..=0x5DF` inside the public `0x500..=0x5FF` window. The
// hex range sits outside the Win32 NT block (`0x540..=0x57F`) so a
// single wire never sees two disjoint label spaces. See
// `userland/core/vfs/src/ipc/protocol/public.rs` for the full layout.
pub const VFS_POSIX_ISATTY: u64 = 0x5C1;
pub const VFS_POSIX_CHDIR: u64 = 0x5C2;
pub const VFS_POSIX_GETCWD: u64 = 0x5C3;
pub const VFS_POSIX_TCGETATTR: u64 = 0x5C4;
pub const VFS_POSIX_TCSETATTR: u64 = 0x5C5;
pub const VFS_POSIX_GETSOCKNAME: u64 = 0x5C6;
pub const VFS_POSIX_GETPEERNAME: u64 = 0x5C7;
pub const VFS_POSIX_SETSOCKOPT: u64 = 0x5C8;
pub const VFS_POSIX_GETSOCKOPT: u64 = 0x5C9;
pub const VFS_MOUNT_LIST: u64 = 0x5CA;
pub const VFS_REMOUNT: u64 = 0x5CB;
pub const VFS_CLIENT_EXIT: u64 = 0x5CC;
pub const VFS_POSIX_STAT_FOR_EXEC: u64 = 0x5CD;
pub const VFS_POSIX_CANON_PATH: u64 = 0x5CE;
pub const VFS_POSIX_UNSHARE: u64 = 0x5CF;
pub const VFS_POSIX_MKFIFO: u64 = 0x5D0;
pub const VFS_POSIX_PTY_READY: u64 = 0x5D1;

/// SaltyOS-private mount flag: enable mount-wide case-insensitive,
/// case-preserving lookup. Deliberately lives above the traditional
/// Linux/BSD `MS_*` bit range so libc-facing flags pass through
/// unchanged while typed mount options such as `casefold` still have
/// a stable wire representation.
pub const VFS_MOUNT_FLAG_CASEFOLD: u64 = 1 << 40;

/// Canonical SaltyOS `MNT_*` mount-flag bits — the wire form carried
/// on the `VFS_MOUNT` request (`regs[3]`) and stored verbatim in the
/// VFS `Mount.mount_flags` low 32 bits (`VFS_MOUNT_FLAG_CASEFOLD`
/// rides bit 40, outside this range). basaltc's `mount(2)` lowers
/// Linux `MS_*` into these via `linux_ms_to_mnt`, and the VFS boot
/// table and `VFS_MOUNT_LIST` use the same set, so boot-time and
/// runtime mounts share one encoding. This layout differs from both
/// Linux `MS_*` and BSD `struct statfs` `MNT_*`; basaltc translates
/// at each ABI edge (`mnt_to_bsd`).
pub const MNT_RDONLY: u32 = 1 << 0;
pub const MNT_NOSUID: u32 = 1 << 1;
pub const MNT_NOEXEC: u32 = 1 << 2;
pub const MNT_NODEV: u32 = 1 << 3;
pub const MNT_BIND: u32 = 1 << 8;
pub const MNT_RBIND: u32 = 1 << 9;
pub const MNT_NOATIME: u32 = 1 << 13;

pub const VFS_POSIX_MKNOD: u64 = 0x5D2;
pub const VFS_POSIX_FGETXATTR: u64 = 0x5D4;
pub const VFS_POSIX_FLISTXATTR: u64 = 0x5D5;
pub const VFS_POSIX_FSETXATTR: u64 = 0x5D6;
pub const VFS_POSIX_FREMOVEXATTR: u64 = 0x5D7;
pub const VFS_POSIX_GET_CTTY_DEV: u64 = 0x5D8;
// ---------------------------------------------------------------------------
// posix_ttysrv — POSIX TTY/PTY personality server.
// ---------------------------------------------------------------------------

pub const POSIX_TTYSRV_GET_FG_PGRP: u64 = 1;
pub const POSIX_TTYSRV_SET_FG_PGRP: u64 = 2;
pub const POSIX_TTYSRV_SET_CTTY: u64 = 3;
pub const POSIX_TTYSRV_DROP_CTTY: u64 = 4;
pub const POSIX_TTYSRV_CTTY_PTY_FOR_SID: u64 = 5;
/// Dump every active session→pty controlling-terminal binding in one
/// round-trip so a caller (vfs) can join `tty_dev` onto a batch of
/// process records without a per-record query. Reply: `regs[0]` = count,
/// `regs[1 + i]` = `(sid in low 32) | (pty_id in high 32)` per binding.
pub const POSIX_TTYSRV_CTTY_DUMP: u64 = 6;
pub const POSIX_TTYSRV_PTY_ALLOC: u64 = 10;
pub const POSIX_TTYSRV_PTY_READ: u64 = 11;
pub const POSIX_TTYSRV_PTY_WRITE: u64 = 12;
pub const POSIX_TTYSRV_PTY_CLOSE: u64 = 13;
pub const POSIX_TTYSRV_PTY_TCGETATTR: u64 = 14;
pub const POSIX_TTYSRV_PTY_TCSETATTR: u64 = 15;
pub const POSIX_TTYSRV_PTY_IOCTL: u64 = 16;
pub const POSIX_TTYSRV_PTY_POLL: u64 = 17;
pub const POSIX_TTYSRV_PTY_COLLECT: u64 = 19;
pub const POSIX_TTYSRV_PTY_MASTER_WRITE: u64 = 20;
pub const POSIX_TTYSRV_CLIENT_EXIT: u64 = 21;
pub const POSIX_TTYSRV_SETUP_INPUT_RING: u64 = 22;
pub const POSIX_TTYSRV_PTY_OPEN_SLAVE: u64 = 23;
pub const POSIX_TTYSRV_PTY_LOOKUP: u64 = 24;
pub const POSIX_TTYSRV_INPUT_KICK: u64 = 25;

// ---------------------------------------------------------------------------
// netdrv / netsrv internal wake labels.
// ---------------------------------------------------------------------------

pub const NETDRV_REGISTER: u64 = 0xC0;
pub const NETDRV_TX_KICK: u64 = 0xC1;
pub const NETSRV_RX_KICK: u64 = 0xC2;

// ---------------------------------------------------------------------------
// dnssrv — DNS resolver. Used by `posix::dns`.
// ---------------------------------------------------------------------------

pub const DNS_RESOLVE: u64 = 0x100;
pub const DNS_REVERSE_LOOKUP: u64 = 0x101;
pub const DNS_CACHE_FLUSH: u64 = 0x102;

// ---------------------------------------------------------------------------
// netsrv — network configuration (used by `gethostname`, getaddrinfo
// fallback before DNS, and by `getsockopt(SOL_SOCKET, SO_RCVBUF)` paths).
// ---------------------------------------------------------------------------

pub const NET_GET_CONFIG: u64 = 0x40;

// ---------------------------------------------------------------------------
// netsrv INET recvmsg wire flags & sentinel — passed in `TronaMsg.regs[]`
// alongside `VFS_POSIX_RECVMSG` to control INET-side recv semantics.
// ---------------------------------------------------------------------------

pub const INET_RECV_FLAG_WANT_ADDR: u32 = 1 << 0;
pub const INET_RECV_FLAG_WANT_TIMESTAMP: u32 = 1 << 1;
pub const INET_RECV_FLAG_PEEK: u32 = 1 << 2;

/// Sentinel used by netsrv to mean "no SO_TIMESTAMP available for this
/// datagram". Must NOT collide with any real monotonic-ns timestamp.
pub const INET_RECV_TIMESTAMP_NONE: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// mmsrv (block 0x400..=0x4FF). Numeric values match
// `trona::protocol::MM_*` where the same operation is reachable from
// both POSIX wrappers (`posix::mm`, `posix::bulk`) and substrate's own
// allocator/probe path; the same mmsrv server handles both callsites.
// ---------------------------------------------------------------------------

pub const MM_MMAP: u64 = 0x410;
pub const MM_MUNMAP: u64 = 0x411;
pub const MM_MPROTECT: u64 = 0x412;
pub const MM_BRK: u64 = 0x413;
pub const MM_SBRK: u64 = 0x414;
pub const MM_SHM_CREATE: u64 = 0x420;
pub const MM_SHM_MAP: u64 = 0x421;
pub const MM_FILE_MMAP: u64 = 0x430;
pub const MM_PREFAULT_RANGE: u64 = 0x440;

// ---------------------------------------------------------------------------
// rsrcsrv (block 0x300..=0x3FF). Numeric value matches
// `trona::protocol::RSRC_ALLOC`.
// ---------------------------------------------------------------------------

pub const RSRC_ALLOC: u64 = 0x300;
