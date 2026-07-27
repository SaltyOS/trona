// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX terminal / poll / device ABI constants — `TIOC*` / `FBIO*` /
//! `POLL*` / `EPOLL*` / `DEV_*` / `TTY_DEV_*` / `tty_dev_for_*`.

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

/// VFS device type constants.
pub const DEV_CONSOLE: u8 = 0;
pub const DEV_NULL: u8 = 1;
pub const DEV_ZERO: u8 = 2;
pub const DEV_FB0: u8 = 3;
pub const DEV_PTY_SLAVE: u8 = 4;
pub const DEV_PTMX: u8 = 5;
pub const DEV_URANDOM: u8 = 6;

/// Synthetic device ids used for terminal identity across procfs
/// and libc.
pub const TTY_DEV_CONSOLE: u64 = 1;
pub const TTY_DEV_PTS_BASE: u64 = 0x1000;

pub const fn tty_dev_for_console() -> u64 {
    TTY_DEV_CONSOLE
}

pub const fn tty_dev_for_pts(pty_id: u64) -> u64 {
    TTY_DEV_PTS_BASE + pty_id
}
