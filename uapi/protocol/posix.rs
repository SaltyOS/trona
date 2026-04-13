// POSIX personality IPC protocol labels.
// SPDX-License-Identifier: GPL-2.0-only
//
// Labels used exclusively by POSIX personality servers (posix_ttysrv, VFS
// POSIX personality handlers). Non-POSIX subsystems must not depend on these.

/// posix_ttysrv IPC labels.
pub const POSIX_TTYSRV_GET_FG_PGRP: u64 = 1;
pub const POSIX_TTYSRV_SET_FG_PGRP: u64 = 2;
pub const POSIX_TTYSRV_SET_CTTY: u64 = 3;
pub const POSIX_TTYSRV_DROP_CTTY: u64 = 4;
pub const POSIX_TTYSRV_PTY_ALLOC: u64 = 10;
pub const POSIX_TTYSRV_PTY_READ: u64 = 11;
pub const POSIX_TTYSRV_PTY_WRITE: u64 = 12;
pub const POSIX_TTYSRV_PTY_CLOSE: u64 = 13;
pub const POSIX_TTYSRV_PTY_TCGETATTR: u64 = 14;
pub const POSIX_TTYSRV_PTY_TCSETATTR: u64 = 15;
pub const POSIX_TTYSRV_PTY_IOCTL: u64 = 16;
pub const POSIX_TTYSRV_PTY_POLL: u64 = 17;
pub const POSIX_TTYSRV_INPUT_EVENT: u64 = 18;
pub const POSIX_TTYSRV_PTY_COLLECT: u64 = 19;
pub const POSIX_TTYSRV_PTY_MASTER_WRITE: u64 = 20;
pub const POSIX_TTYSRV_CLIENT_EXIT: u64 = 21;

/// POSIX-only VFS labels (terminal, fcntl — not part of core VFS protocol).
pub const VFS_POSIX_ISATTY: u64 = 34;
pub const VFS_POSIX_FCNTL: u64 = 35;
