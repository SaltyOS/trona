// Server-to-server and driver IPC protocol labels.
// SPDX-License-Identifier: GPL-2.0-only

/// Console server IPC labels.
pub const CONSOLE_WRITE: u64 = 1;
pub const CONSOLE_READ: u64 = 2;
pub const CONSOLE_TCGETATTR: u64 = 3;
pub const CONSOLE_TCSETATTR: u64 = 4;

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

/// Display server IPC labels.
pub const DISPLAY_GET_INFO: u64 = 1;
pub const DISPLAY_PRESENT: u64 = 2;
pub const DISPLAY_FILL_RECT: u64 = 6;
pub const DISPLAY_WRITE_TEXT: u64 = 7;
pub const DISPLAY_TERMINAL_WRITE: u64 = 8;
pub const DISPLAY_SETUP_RING: u64 = 9;

/// PCI enumeration server IPC labels.
pub const PCI_FIND_DEVICE: u64 = 1;
pub const PCI_GET_CAPS: u64 = 2;
pub const PCI_LIST: u64 = 3;
pub const PCI_READ_CONFIG32: u64 = 4;
pub const PCI_GET_BAR_CAP: u64 = 5;
pub const PCI_WRITE_CONFIG32: u64 = 6;

/// Block device driver IPC labels.
pub const BLK_READ: u64 = 1;
pub const BLK_WRITE: u64 = 2;
pub const BLK_GET_INFO: u64 = 3;
pub const BLK_FLUSH: u64 = 4;
pub const BLK_GET_SHM_ID: u64 = 5;

/// SaltyFS server IPC labels.
pub const SALTYFS_MOUNT: u64 = 1;
pub const SALTYFS_LOOKUP: u64 = 2;
pub const SALTYFS_READ: u64 = 3;
pub const SALTYFS_READDIR: u64 = 4;
pub const SALTYFS_STAT: u64 = 5;
pub const SALTYFS_GETINFO: u64 = 6;
pub const SALTYFS_READ_INLINE: u64 = 7;
pub const SALTYFS_WRITE_INLINE: u64 = 8;
pub const SALTYFS_CREATE: u64 = 9;
pub const SALTYFS_MKDIR: u64 = 10;
pub const SALTYFS_UNLINK: u64 = 11;
pub const SALTYFS_RMDIR: u64 = 12;
pub const SALTYFS_RENAME: u64 = 13;
pub const SALTYFS_TRUNCATE: u64 = 14;
pub const SALTYFS_SHM_SETUP: u64 = 15;
pub const SALTYFS_WRITE: u64 = 16;
pub const SALTYFS_SYMLINK: u64 = 17;
pub const SALTYFS_READLINK: u64 = 18;
pub const SALTYFS_LINK: u64 = 19;
pub const SALTYFS_GETPARENT: u64 = 20;

/// Network stack IPC labels (netsrv protocol).
pub const NET_SOCKET: u64 = 0xA0;
pub const NET_CONNECT: u64 = 0xA1;
pub const NET_SEND: u64 = 0xA2;
pub const NET_RECV: u64 = 0xA3;
pub const NET_CLOSE: u64 = 0xA4;
pub const NET_BIND: u64 = 0xA5;
pub const NET_LISTEN: u64 = 0xA6;
pub const NET_ACCEPT: u64 = 0xA7;
pub const NET_SENDTO: u64 = 0xA8;
pub const NET_RECVFROM: u64 = 0xA9;
pub const NET_SHUTDOWN: u64 = 0xAA;
pub const NET_GETSOCKNAME: u64 = 0xAB;
pub const NET_GETPEERNAME: u64 = 0xAC;
pub const NET_SETSOCKOPT: u64 = 0xAD;
pub const NET_GETSOCKOPT: u64 = 0xAE;
pub const NET_POLL_STATUS: u64 = 0xAF;
pub const NET_REGISTER_VFS: u64 = 0xB0;
pub const NET_COMPLETE: u64 = 0xB1;
pub const NET_DNS_RESOLVE: u64 = 0xB2;
pub const NET_DNS_RESOLVE_PTR: u64 = 0xB3;
pub const NET_GET_CONFIG: u64 = 0xB4;
pub const NET_GET_ARP_ENTRY: u64 = 0xB5;
pub const NET_RECV_WAIT: u64 = 0xB6;
pub const NET_ACCEPT_WAIT: u64 = 0xB7;
pub const NET_RECVFROM_WAIT: u64 = 0xB8;
pub const NET_SEND_WAIT: u64 = 0xB9;
pub const NET_SENDTO_WAIT: u64 = 0xBA;

/// DNS service IPC labels (dnssrv client protocol).
pub const DNS_RESOLVE: u64 = 1;
pub const DNS_CACHE_FLUSH: u64 = 2;
pub const DNS_REVERSE_LOOKUP: u64 = 3;

/// Driver registration IPC labels (driver<->server protocol).
pub const DRIVER_REGISTER: u64 = 0xC0;
pub const DRIVER_GET_INFO: u64 = 0xC1;
