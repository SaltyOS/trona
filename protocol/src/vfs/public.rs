// SPDX-License-Identifier: GPL-2.0-only
//
//! VFS public wire (block 0x500..=0x5FF). Client-facing typed RPC.
//!
//! This module is the single source for cross-process VFS labels,
//! reply labels, and inline payload limits. VFS server code, POSIX
//! wrappers, Win32 wrappers, and substrate helpers all import these
//! values directly; server-private modules must not keep local copies.

pub const VFS_OPEN: u64 = 0x500;
pub const VFS_CLOSE: u64 = 0x501;
pub const VFS_READ: u64 = 0x502;
pub const VFS_WRITE: u64 = 0x503;
pub const VFS_SEEK: u64 = 0x504;
pub const VFS_STAT: u64 = 0x505;
pub const VFS_FSTAT: u64 = 0x506;
pub const VFS_FSTATAT: u64 = 0x507;
pub const VFS_LSTAT: u64 = 0x508;
pub const VFS_TRUNCATE: u64 = 0x509;
pub const VFS_FTRUNCATE: u64 = 0x50A;
pub const VFS_FSYNC: u64 = 0x50B;
pub const VFS_FDATASYNC: u64 = 0x50C;
pub const VFS_DUP: u64 = 0x50D;
pub const VFS_DUP2: u64 = 0x50E;
pub const VFS_DUP3: u64 = 0x50F;
pub const VFS_FCNTL: u64 = 0x510;
pub const VFS_IOCTL: u64 = 0x511;
pub const VFS_OPENAT: u64 = 0x512;
pub const VFS_ACCESS: u64 = 0x513;
pub const VFS_FACCESSAT: u64 = 0x514;
pub const VFS_CHMOD: u64 = 0x515;
pub const VFS_FCHMOD: u64 = 0x516;
pub const VFS_CHOWN: u64 = 0x517;
pub const VFS_FCHOWN: u64 = 0x518;
pub const VFS_UTIMES: u64 = 0x519;
pub const VFS_FUTIMES: u64 = 0x51A;
pub const VFS_READLINK: u64 = 0x51B;
pub const VFS_GETDENTS: u64 = 0x51C;
pub const VFS_MKDIR: u64 = 0x51D;
pub const VFS_RMDIR: u64 = 0x51E;
pub const VFS_LINK: u64 = 0x51F;
pub const VFS_UNLINK: u64 = 0x520;
pub const VFS_SYMLINK: u64 = 0x521;
pub const VFS_RENAME: u64 = 0x522;
pub const VFS_MOUNT: u64 = 0x523;
pub const VFS_UMOUNT: u64 = 0x524;
pub const VFS_STATVFS: u64 = 0x525;
// `0x526` previously held `VFS_MMAP`; the file-backed mmap path is
// now `VFS_GET_BACKING_MO` followed by client-local `MM_MMAP(kind=MO)`.

/// `VFS_GET_BACKING_MO(fd, offset, length) -> (mo_size, mo_offset,
/// mmap_kind, backing_id, backing_length; caps=[backing_cap])` —
/// return a cap that can back a client-side mapping. Regular files
/// return a pager-attached MO cap with `mmap_kind=MMAP_KIND_MO`;
/// device nodes that expose direct mappings return their device cap
/// with `mmap_kind=MMAP_KIND_DEVICE`. The second step is always the
/// caller's own `MM_MMAP(kind=mmap_kind, caps[0]=backing_cap, ...,
/// mo_offset/device_offset)`.
pub const VFS_GET_BACKING_MO: u64 = 0x527;
pub const VFS_BACKING_MO_REPLY_REG_SIZE: usize = 0;
pub const VFS_BACKING_MO_REPLY_REG_OFFSET: usize = 1;
pub const VFS_BACKING_MO_REPLY_REG_MMAP_KIND: usize = 2;
pub const VFS_BACKING_MO_REPLY_REG_BACKING_ID: usize = 3;
pub const VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH: usize = 4;
pub const VFS_BACKING_MO_REPLY_REQUIRED_REGS: u64 = 3;
pub const VFS_BACKING_MO_REPLY_REG_COUNT: u64 = 5;
pub const VFS_POLL: u64 = 0x528;
pub const VFS_EPOLL_CREATE: u64 = 0x529;
pub const VFS_EPOLL_CTL: u64 = 0x52A;
pub const VFS_EPOLL_WAIT: u64 = 0x52B;
// 0x52C is free (was VFS_SHM_CREATE; shm create now folds into VFS_SHM_OPEN
// via the O_CREAT flag, matching VFS_OPEN).
pub const VFS_SHM_OPEN: u64 = 0x52D;
pub const VFS_SHM_UNLINK: u64 = 0x52E;
pub const VFS_PIPE: u64 = 0x52F;
pub const VFS_PIPE2: u64 = 0x530;
pub const VFS_FIFO_OPEN: u64 = 0x531;
pub const VFS_SOCKET: u64 = 0x532;
pub const VFS_SOCKETPAIR: u64 = 0x533;
pub const VFS_BIND: u64 = 0x534;
pub const VFS_LISTEN: u64 = 0x535;
pub const VFS_ACCEPT: u64 = 0x536;
pub const VFS_CONNECT: u64 = 0x537;
pub const VFS_SHUTDOWN: u64 = 0x538;
pub const VFS_SEND: u64 = 0x539;
pub const VFS_RECV: u64 = 0x53A;
/// `VFS_MSYNC_MO(mo_id, mo_offset, length, flags)` — mmsrv asks VFS,
/// the file-pager owner, to write back dirty resident page-cache pages for a
/// shared file-backed mapping range. This is server-to-server plumbing; normal
/// clients reach it only through `MM_MSYNC` / `MM_MUNMAP`.
pub const VFS_MSYNC_MO: u64 = 0x53B;
pub const VFS_REGISTER_BULK_SHM: u64 = 0x53C;
pub const VFS_RELEASE_BULK_SHM: u64 = 0x53D;
pub const VFS_BULK_SHM_REPLY_REG_BYTES: usize = 0;
pub const VFS_BULK_SHM_REPLY_REG_SHM_IDX: usize = 1;
pub const VFS_BULK_SHM_REPLY_REG_TOKEN: usize = 2;
pub const VFS_BULK_SHM_REPLY_REG_COUNT: u64 = 3;

pub const VFS_ISATTY: u64 = 0x5C1;
pub const VFS_CHDIR: u64 = 0x5C2;
pub const VFS_GETCWD: u64 = 0x5C3;
pub const VFS_TCGETATTR: u64 = 0x5C4;
pub const VFS_TCSETATTR: u64 = 0x5C5;
pub const VFS_GETSOCKNAME: u64 = 0x5C6;
pub const VFS_GETPEERNAME: u64 = 0x5C7;
pub const VFS_SETSOCKOPT: u64 = 0x5C8;
pub const VFS_GETSOCKOPT: u64 = 0x5C9;
pub const VFS_MOUNT_LIST: u64 = 0x5CA;
pub const VFS_REMOUNT: u64 = 0x5CB;
pub const VFS_CLIENT_EXIT: u64 = 0x5CC;
pub const VFS_STAT_FOR_EXEC: u64 = 0x5CD;
pub const VFS_CANON_PATH: u64 = 0x5CE;
pub const VFS_UNSHARE: u64 = 0x5CF;
pub const VFS_MKFIFO: u64 = 0x5D0;
pub const VFS_PTY_READY: u64 = 0x5D1;
pub const VFS_MKNOD: u64 = 0x5D2;
pub const VFS_FGETXATTR: u64 = 0x5D4;
pub const VFS_FLISTXATTR: u64 = 0x5D5;
pub const VFS_FSETXATTR: u64 = 0x5D6;
pub const VFS_FREMOVEXATTR: u64 = 0x5D7;
pub const VFS_GET_CTTY_DEV: u64 = 0x5D8;
/// Resolve a path with the caller's vfs authority (cwd + cred), enforce
/// exec policy (regular file, caller execute permission, mount not
/// `MNT_NOEXEC`), and reply with a non-exec `READ|GRANT|TRANSFER`
/// MemoryObject cap for the file in `caps[0]` plus `regs[0] = exact_size` and
/// `regs[1] = image byte offset` within that backing. The caller cap-transfers
/// that MO, size, and offset to init; ldsrv confers EXECUTE through the exec
/// authority. Distinct from `VFS_GET_BACKING_MO` (which grants mmap rights)
/// and `VFS_STAT_FOR_EXEC` (preflight only, no MO).
pub const VFS_OPEN_FOR_EXEC: u64 = 0x5D9;

/// Bootstrap-bind against the namesrv-published VFS master endpoint.
/// The reply carries `caps[0] = per-client VFS request MessagePipe send`.
/// Regular VFS RPC labels must use that returned cap, not the shared
/// master endpoint, so concurrent callers cannot consume one another's
/// replies from the master queue.
pub const VFS_BIND_CLIENT_SELF: u64 = 0x5E0;

/// Supervisor-only teardown notice: init's `finalize_exit` invokes the dead
/// process's control cap with this label (fire-and-forget `MP_WRITE`) on
/// exit, so vfs reclaims the client's per-client resources (request-MP pair +
/// Watch + ClientState). vfs has no other reliable signal of client death:
/// the request MP stays open because vfs retains its own send side, and no
/// client sends an exit notice itself. The control-cap badge both authorizes
/// the teardown and names the target client, so no client can tear down
/// another's connection.
pub const VFS_DEREGISTER_CLIENT: u64 = 0x5E1;

/// init-driven client registration (authorized by the per-server ROOT control
/// cap). `regs[0]` carries the process's `client_id`, `regs[1]` carries its
/// PID. vfs creates a pre-bound `ClientState` keyed by the supplied
/// `client_id`, records the PID in the client's credential snapshot, mints a
/// per-client control cap, and returns it in `caps[0]`.
/// The child later adopts this entry when it self-binds.
pub const VFS_ADMIN_REGISTER_CLIENT: u64 = 0x5E2;

/// init-driven fork FD-clone, step 2 (operate): invoked on the PARENT's
/// control cap with the same `nonce` as the preceding
/// `VFS_ADMIN_CLONE_SET_PARTNER`. vfs clones the parent client's FD table
/// (aliased OpenObject handles, FD_CLOEXEC flags, cred / cwd / mount-ns) into
/// the child pinned by the pending partner.
pub const VFS_ADMIN_CLONE_FDS: u64 = 0x5E3;

/// init-driven fork FD-clone, step 1 (pin the child): invoked on the CHILD's
/// control cap with a `nonce`. vfs records the child as the pending clone
/// partner; the matching `VFS_ADMIN_CLONE_FDS` on the parent consumes it. A
/// badge surfaces only on invoke, so the second operand cannot ride as a
/// transferred cap.
pub const VFS_ADMIN_CLONE_SET_PARTNER: u64 = 0x5E4;

/// init-driven exec `FD_CLOEXEC` sweep: invoked on the exec'ing client's
/// control cap after the exec point of no return. vfs drops the client's
/// FD_CLOEXEC descriptors. Best-effort — it only frees state and its failure
/// cannot fail the already-committed exec.
pub const VFS_ADMIN_EXEC_SWEEP: u64 = 0x5E5;

pub const VFS_OPENDIR: u64 = VFS_OPEN;
pub const VFS_READDIR: u64 = VFS_GETDENTS;
pub const VFS_UNLINKAT: u64 = VFS_UNLINK;
pub const VFS_RENAMEAT: u64 = VFS_RENAME;
pub const VFS_MKDIRAT: u64 = VFS_MKDIR;
pub const VFS_FCHMODAT: u64 = VFS_FCHMOD;
pub const VFS_FCHOWNAT: u64 = VFS_FCHOWN;
pub const VFS_LINKAT: u64 = VFS_LINK;
pub const VFS_SYMLINKAT: u64 = VFS_SYMLINK;
pub const VFS_READLINKAT: u64 = VFS_READLINK;
pub const VFS_UTIMENSAT: u64 = VFS_UTIMES;
pub const VFS_SENDMSG: u64 = VFS_SEND;
pub const VFS_RECVMSG: u64 = VFS_RECV;

pub const VFS_RW_FLAG_SHM: u64 = 1 << 0;

pub const VFS_PUBLIC_PATH_MAX: usize = 128;
pub const VFS_INLINE_READ_MAX: usize = 224;
pub const VFS_INLINE_WRITE_MAX: usize = 224;

/// `VFS_SEND` / `VFS_SENDMSG` flag: inline destination address is an
/// AF_UNIX local path packed after the flag word.
pub const VFS_SENDMSG_FLAG_LOCAL_ADDR: u32 = 1 << 31;
/// `VFS_SEND` / `VFS_SENDMSG` flag: inline destination address is
/// an AF_INET `(ip, port)` tuple in regs[3..=4].
pub const VFS_SENDMSG_FLAG_INET_ADDR: u32 = 1 << 30;
/// `VFS_RECV` / `VFS_RECVMSG` flag: caller wants received
/// SCM_RIGHTS descriptors installed into its fd table.
pub const VFS_RECVMSG_FLAG_WANT_RIGHTS: u32 = 1 << 30;
/// `VFS_RECV` / `VFS_RECVMSG` flag: caller wants the source address
/// projected into the reply.
pub const VFS_RECVMSG_FLAG_WANT_ADDR: u32 = 1 << 29;

pub const VFS_PUBLIC_REPLY_OK: u64 = 0;
pub const VFS_PUBLIC_REPLY_BAD_F: u64 = 0x5F01;
pub const VFS_PUBLIC_REPLY_NOT_FOUND: u64 = 0x5F02;
pub const VFS_PUBLIC_REPLY_PERM: u64 = 0x5F03;
pub const VFS_PUBLIC_REPLY_BUSY: u64 = 0x5F04;
pub const VFS_PUBLIC_REPLY_IO_ERROR: u64 = 0x5F05;
pub const VFS_PUBLIC_REPLY_INVALID: u64 = 0x5F06;
pub const VFS_PUBLIC_REPLY_NO_MEM: u64 = 0x5F07;
pub const VFS_PUBLIC_REPLY_LOOP: u64 = 0x5F08;
pub const VFS_PUBLIC_REPLY_NAME_TOO_LONG: u64 = 0x5F09;
pub const VFS_PUBLIC_REPLY_NOT_DIR: u64 = 0x5F0A;
pub const VFS_PUBLIC_REPLY_IS_DIR: u64 = 0x5F0B;
pub const VFS_PUBLIC_REPLY_NOT_EMPTY: u64 = 0x5F0C;
pub const VFS_PUBLIC_REPLY_X_DEV: u64 = 0x5F0D;
pub const VFS_PUBLIC_REPLY_RO_FS: u64 = 0x5F0E;
pub const VFS_PUBLIC_REPLY_NOT_SUPPORTED: u64 = 0x5F0F;
pub const VFS_PUBLIC_REPLY_AGAIN: u64 = 0x5F10;
pub const VFS_PUBLIC_REPLY_INTR: u64 = 0x5F11;
pub const VFS_PUBLIC_REPLY_TIMED_OUT: u64 = 0x5F12;
pub const VFS_PUBLIC_REPLY_QUOTA: u64 = 0x5F13;
pub const VFS_PUBLIC_REPLY_EXIST: u64 = 0x5F14;
pub const VFS_PUBLIC_REPLY_SESSION_TORN_DOWN: u64 = 0x5F15;
pub const VFS_PUBLIC_REPLY_PREDECESSOR_FAILED: u64 = 0x5F16;
pub const VFS_PUBLIC_REPLY_STALE_INCARNATION: u64 = 0x5F17;
pub const VFS_PUBLIC_REPLY_NOT_TTY: u64 = 0x5F18;
pub const VFS_PUBLIC_REPLY_RANGE: u64 = 0x5F19;
