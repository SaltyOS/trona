// SPDX-License-Identifier: GPL-2.0-only
//
//! Cross-server reply / status conventions independent of any
//! single namespace.

/// Reply label that supervisor RPCs (init / mmsrv / rsrcsrv / namesrv)
/// echo back in `TronaMsg.label` to mark "the request succeeded; payload
/// follows in `regs[]`". Userland convention only — independent of
/// the kernel ABI's `KERNITE_OK` error code.
pub const TRONA_OK: u64 = 0;
/// Reply label for asynchronous server operations whose completion will
/// arrive on a later callback path.
pub const TRONA_PENDING: u64 = 0x80;

/// Stable userland reply labels for generic service failures.
///
/// These are deliberately not `KERNITE_ERR_*` values. Kernel invocation
/// errors may still be forwarded explicitly by low-level services, but
/// server protocol replies must live in this userland namespace.
pub const TRONA_STATUS_BASE: u64 = 0x7000;
pub const TRONA_INVALID_CAPABILITY: u64 = TRONA_STATUS_BASE + 0x01;
pub const TRONA_INVALID_OPERATION: u64 = TRONA_STATUS_BASE + 0x02;
pub const TRONA_PERMISSION_DENIED: u64 = TRONA_STATUS_BASE + 0x03;
pub const TRONA_INVALID_ARGUMENT: u64 = TRONA_STATUS_BASE + 0x04;
pub const TRONA_OUT_OF_MEMORY: u64 = TRONA_STATUS_BASE + 0x05;
pub const TRONA_NOT_FOUND: u64 = TRONA_STATUS_BASE + 0x06;
pub const TRONA_BUSY: u64 = TRONA_STATUS_BASE + 0x07;
pub const TRONA_ALREADY_EXISTS: u64 = TRONA_STATUS_BASE + 0x08;
pub const TRONA_WOULD_BLOCK: u64 = TRONA_STATUS_BASE + 0x09;
pub const TRONA_BAD_ADDRESS: u64 = TRONA_STATUS_BASE + 0x0A;
pub const TRONA_OUT_OF_RANGE: u64 = TRONA_STATUS_BASE + 0x0B;
pub const TRONA_CANCELLED: u64 = TRONA_STATUS_BASE + 0x0C;
pub const TRONA_DEADLOCK: u64 = TRONA_STATUS_BASE + 0x0D;
pub const TRONA_TIMED_OUT: u64 = TRONA_STATUS_BASE + 0x0E;
pub const TRONA_TOO_LARGE: u64 = TRONA_STATUS_BASE + 0x10;
pub const TRONA_NOT_SUPPORTED: u64 = TRONA_STATUS_BASE + 0x11;
pub const TRONA_READONLY: u64 = TRONA_STATUS_BASE + 0x12;
pub const TRONA_IO_ERROR: u64 = TRONA_STATUS_BASE + 0x1A;
