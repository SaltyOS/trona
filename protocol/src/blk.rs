// SPDX-License-Identifier: GPL-2.0-only
//
//! blkdrv wire labels.
//!
//! Used by storage backends such as saltyfs to talk directly to blkdrv. This
//! is intentionally separate from `vfs::backend`: blkdrv is a block-device
//! service, not a filesystem backend mount instance.

pub const BLK_READ: u64 = 1;
pub const BLK_WRITE: u64 = 2;
pub const BLK_GET_INFO: u64 = 3;
pub const BLK_FLUSH: u64 = 4;
/// Reply: `regs[0] = mmsrv shm index`, `caps[0] = SHM MO cap` for
/// the caller's `MM_SHM_MAP`.
pub const BLK_GET_SHM_ID: u64 = 5;
