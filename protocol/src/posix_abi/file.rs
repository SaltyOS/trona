// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX file ABI constants — open flags, seek whence, stat mode bits,
//! dirent types, waitpid options, AT_* / UTIME_*, fcntl commands,
//! `FD_CLOEXEC`, `DEFAULT_PATH`, `NGROUPS_MAX`.

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
pub const WUNTRACED: u64 = 2;
pub const WCONTINUED: u64 = 8;

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

/// Default search PATH for program execution.
pub const DEFAULT_PATH: &[u8] = b"/bin:/sbin:/usr/bin:/usr/sbin";
pub const DEFAULT_PATH_NUL: &[u8] = b"/bin:/sbin:/usr/bin:/usr/sbin\0";
