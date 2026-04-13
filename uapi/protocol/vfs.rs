// VFS server IPC protocol labels.
// SPDX-License-Identifier: GPL-2.0-only

pub const VFS_POSIX_OPEN: u64 = 1;
pub const VFS_READ: u64 = 2;
pub const VFS_WRITE: u64 = 3;
pub const VFS_CLOSE: u64 = 4;
pub const VFS_POSIX_STAT: u64 = 5;
pub const VFS_LSEEK: u64 = 6;
pub const VFS_POSIX_FSTAT: u64 = 7;
pub const VFS_POSIX_ACCESS: u64 = 8;
pub const VFS_POSIX_UNLINK: u64 = 9;
pub const VFS_POSIX_RENAME: u64 = 10;
pub const VFS_POSIX_MKDIR: u64 = 11;
pub const VFS_POSIX_RMDIR: u64 = 12;
pub const VFS_POSIX_OPENDIR: u64 = 13;
pub const VFS_POSIX_READDIR: u64 = 14;
pub const VFS_POSIX_LSTAT: u64 = 15;
pub const VFS_POSIX_POLL: u64 = 16;
pub const VFS_POSIX_SHM_OPEN: u64 = 17;
pub const VFS_POSIX_SHM_UNLINK: u64 = 18;
pub const VFS_POSIX_FTRUNCATE: u64 = 19;
pub const VFS_POSIX_SOCKET: u64 = 20;
pub const VFS_POSIX_BIND: u64 = 21;
pub const VFS_POSIX_LISTEN: u64 = 22;
pub const VFS_POSIX_ACCEPT: u64 = 23;
pub const VFS_POSIX_CONNECT: u64 = 24;
pub const VFS_POSIX_SENDMSG: u64 = 25;
pub const VFS_POSIX_RECVMSG: u64 = 26;
pub const VFS_POSIX_SOCKPAIR: u64 = 27;
pub const VFS_POSIX_SHUTDOWN: u64 = 28;
pub const VFS_POSIX_PIPE: u64 = 29;
pub const VFS_POSIX_DUP: u64 = 30;
pub const VFS_POSIX_DUP2: u64 = 31;
pub const VFS_POSIX_CLONE_FDS: u64 = 32;
pub const VFS_POSIX_IOCTL: u64 = 33;
// 34-35 moved to protocol/posix.rs (VFS_POSIX_ISATTY, VFS_POSIX_FCNTL — POSIX-only)
pub const VFS_POSIX_CHDIR: u64 = 36;
pub const VFS_POSIX_GETCWD: u64 = 37;
pub const VFS_POSIX_TCGETATTR: u64 = 38;
pub const VFS_POSIX_TCSETATTR: u64 = 39;
pub const VFS_POSIX_EPOLL_CREATE: u64 = 40;
pub const VFS_POSIX_EPOLL_CTL: u64 = 41;
pub const VFS_POSIX_EPOLL_WAIT: u64 = 42;
pub const VFS_POSIX_DUP3: u64 = 43;
pub const VFS_POSIX_MKFIFO: u64 = 44;
// 45-46 removed: mmap is now owned by mmsrv (MM_FILE_MMAP)
pub const VFS_POSIX_OPENAT: u64 = 47;
pub const VFS_POSIX_FSTATAT: u64 = 48;
pub const VFS_POSIX_UNLINKAT: u64 = 49;
pub const VFS_POSIX_RENAMEAT: u64 = 50;
pub const VFS_POSIX_MKDIRAT: u64 = 51;
pub const VFS_POSIX_FACCESSAT: u64 = 52;
pub const VFS_POSIX_FCHMODAT: u64 = 53;
pub const VFS_POSIX_FCHOWNAT: u64 = 54;
pub const VFS_POSIX_LINKAT: u64 = 55;
pub const VFS_POSIX_SYMLINKAT: u64 = 56;
pub const VFS_POSIX_READLINKAT: u64 = 57;
pub const VFS_POSIX_UTIMENSAT: u64 = 58;
pub const VFS_POSIX_FCHMOD: u64 = 59;
pub const VFS_POSIX_FCHOWN: u64 = 60;
pub const VFS_CLIENT_EXIT: u64 = 61;
pub const VFS_PREAD: u64 = 62;
pub const VFS_PWRITE: u64 = 63;
pub const VFS_BULK_SETUP: u64 = 64;
pub const VFS_BULK_READ: u64 = 65;
pub const VFS_POSIX_GETSOCKNAME: u64 = 66;
pub const VFS_POSIX_GETPEERNAME: u64 = 67;
pub const VFS_POSIX_SETSOCKOPT: u64 = 68;
pub const VFS_POSIX_GETSOCKOPT: u64 = 69;
pub const VFS_BACKEND_PAGER_READ: u64 = 70;
pub const VFS_BACKEND_PAGER_WRITE: u64 = 71;
pub const VFS_BULK_PWRITE: u64 = 72;
pub const VFS_BACKEND_RESOLVE_BACKING: u64 = 73;
pub const VFS_DUMP_PENDING: u64 = 75;

// Multi-user permission and persistence
pub const VFS_POSIX_STAT_FOR_EXEC: u64 = 76;
pub const VFS_FSYNC: u64 = 77;
pub const VFS_GETXATTR: u64 = 78;
pub const VFS_SETXATTR: u64 = 79;
pub const VFS_REMOVEXATTR: u64 = 80;
pub const VFS_LISTXATTR: u64 = 81;

// Mount operations
pub const VFS_MOUNT: u64 = 82;
pub const VFS_UMOUNT: u64 = 83;
pub const VFS_PIVOT_ROOT: u64 = 84;

// Personality registration
pub const VFS_CLIENT_REGISTER: u64 = 85;

// Sysctl
pub const VFS_SYSCTL: u64 = 86;

// Exec path canonicalization
pub const VFS_POSIX_CANON_PATH: u64 = 87;

// Win32 CreateFile — carries native dwDesiredAccess, dwShareMode,
// dwCreationDisposition, and dwFlagsAndAttributes so the VFS can
// perform proper share-mode arbitration without lossy POSIX translation.
//
// Wire format:
//   regs[0] = dwDesiredAccess
//   regs[1] = dwShareMode
//   regs[2] = dwCreationDisposition
//   regs[3] = dwFlagsAndAttributes
//   regs[4] = path_len
//   regs[5..] = path_bytes (inline UTF-8)
pub const VFS_WIN32_OPEN: u64 = 88;

// Mount namespace operations
// regs[0] = flags (CLONE_NEWNS = 0x00020000)
pub const VFS_POSIX_UNSHARE: u64 = 89;
/// Exec transition cleanup for an existing VFS client badge.
pub const VFS_CLIENT_EXEC: u64 = 90;
