// SPDX-License-Identifier: GPL-2.0-only
//
//! Userland log service wire labels.
//!
//! Logs are ordinary userspace IPC. `KernelDebug` remains a privileged
//! kernel-debug capability; non-privileged services send diagnostic
//! output to `logsrv`, which forwards it through the privileged
//! kernel-debug sink.

/// Send-only log record.
///
/// Wire shape:
/// - `regs[0]`: byte length
/// - `regs[1..]`: inline bytes, packed little-endian
///
/// The sender uses `MP_WRITE`; no reply is expected.
pub const LOG_WRITE: u64 = 0x700;

/// Maximum payload carried inline in one `LOG_WRITE` message.
pub const LOG_INLINE_BYTES: usize = 31 * 8;
