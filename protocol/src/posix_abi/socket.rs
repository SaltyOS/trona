// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX socket ABI constants — `AF_*` / `SOCK_*` / `IPPROTO_*` /
//! `SCM_*` / `MSG_CMSG_CLOEXEC` / `SOL_SOCKET` / `SO_*` / `IP_TTL` /
//! `SHUT_*`.

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
/// `recvmsg` flag — install received SCM_RIGHTS fds with
/// `FD_CLOEXEC`. Matches the Linux value so POSIX code that uses the
/// libc constant does not need translation.
pub const MSG_CMSG_CLOEXEC: i32 = 0x40000000;
pub const SOL_SOCKET: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_BROADCAST: i32 = 6;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_ACCEPTCONN: i32 = 30;
pub const SO_TIMESTAMP: i32 = 0x0000_0400;
pub const SO_PROTOCOL: i32 = 38;
pub const SO_DOMAIN: i32 = 39;
pub const SO_TS_CLOCK: i32 = 0x1017;
pub const SO_TS_MONOTONIC: i32 = 3;
pub const IP_TTL: i32 = 2;
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;
