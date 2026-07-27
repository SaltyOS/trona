// SPDX-License-Identifier: GPL-2.0-only
//
//! VFS protocol — two sub-namespaces split by interaction surface:
//!
//! * `public` — client-facing typed RPC (block 0x500..=0x5FF).
//! * `backend` — vfs ↔ saltyfs / netsrv / blkdrv / posix_ttysrv
//!   (block 0x600..=0x6FF).
//!
//! The former `pager` namespace (block 0x700..=0x7FF) is gone —
//! file-backed page faults are now routed by the kernel directly
//! to vfs's `OBJ_PAGER` event queue (`KERNITE_EVENT_TYPE_PAGER_REQUEST`)
//! instead of bouncing through mmsrv via userland-defined RPC. mmsrv
//! ↔ vfs only retains the `MM_REGISTER_VFS_PAGER` self-tier admission
//! (in the `mm` namespace).
//!
//! Two algorithm-shaped utilities also live under this namespace
//! because the same fold is required cross-server (saltyfs daemon
//! + win32 personality + vfs frontend all consult one table):
//!
//! * `casefold` — Unicode 15.1 simple case-folding utility.
//! * `casefold_table` — 1457-entry generated table.

pub mod backend;
pub mod casefold;
pub(crate) mod casefold_table;
pub mod public;
