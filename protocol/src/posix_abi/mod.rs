// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX-shaped wire ABI constants — file flags, mmap flags, socket
//! types, terminal ioctls.
//!
//! These are the lower-level POSIX-compatible numeric constants that
//! cross the wire between userland servers and POSIX clients. Both
//! POSIX-personality wrappers (`trona_posix`) and personality-neutral
//! servers (init / netsrv / dispdrv / procmgr / win32_csrss) depend on
//! these — the values must be POSIX-compatible because clients invoke
//! them through libc surfaces (`open(O_RDONLY)`, `socket(SOCK_DGRAM)`,
//! `ioctl(TIOCSCTTY)`, etc.) and the server side must echo the same
//! numeric encoding back over the wire.
//!
//! Splitting these out of the POSIX personality crate keeps the
//! invariant that personality-neutral servers do **not** import
//! `trona_posix::*` while still letting them speak POSIX-compatible
//! wire values. The POSIX personality crate re-exports the same
//! constants from `trona_posix::consts` so existing POSIX wrapper
//! code paths are unchanged.
//!
//! Sub-modules:
//! - `file` — `O_*` / `SEEK_*` / `S_IF*` / permission bits / `DT_*` /
//!   waitpid / `AT_*` / `UTIME_*` / `F_*` (fcntl) / `FD_CLOEXEC` /
//!   `DEFAULT_PATH` / `NGROUPS_MAX`
//! - `mm`   — `PROT_*` / `MAP_*`
//! - `socket` — `AF_*` / `SOCK_*` / `IPPROTO_*` / `SCM_*` /
//!   `MSG_CMSG_CLOEXEC` / `SOL_SOCKET` / `SO_*` / `IP_TTL` / `SHUT_*`
//! - `time` — POSIX `clockid_t` values
//! - `tty`   — `TIOC*` / `FBIO*` / `POLL*` / `EPOLL*` / `DEV_*` /
//!   `TTY_DEV_*` / `tty_dev_for_*`

pub mod file;
pub mod mm;
pub mod socket;
pub mod time;
pub mod tty;
