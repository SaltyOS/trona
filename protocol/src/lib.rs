// SPDX-License-Identifier: GPL-2.0-only
//
//! trona_protocol — cross-server wire constants and shapes.
//!
//! Single source of truth for the userland-server protocol labels,
//! reply payload shapes, and bookkeeping types that the various
//! servers (init / namesrv / rsrcsrv / mmsrv / vfs / netsrv /
//! saltyfs / posix / win32) exchange. The kernel ABI itself lives in
//! `uapi`; this crate is one layer above and one layer below the
//! servers themselves.
//!
//! Self-contained — depends only on `uapi` (kernel ABI const +
//! shape) and the Rust `core` crate. Wire-length helpers take
//! `&mut u64` directly so this crate compiles on the saltyos
//! target *and* the PE target (kernel32.dll) from the same source
//! without cfg gates or per-target shims. Server crates import
//! `trona_protocol::<server>::*` to dispatch; caller crates
//! import the same labels to invoke. Drift between caller and
//! dispatcher is impossible because both consult one const file.
//!
//! Namespace layout (block convention identical to the original
//! substrate/protocol.rs documentation, re-anchored per crate):
//!
//! | Block         | Namespace                        |
//! |---------------|----------------------------------|
//! | 0x100..=0x1FF | `init`                           |
//! | 0x200..=0x2FF | `namesrv`                        |
//! | 0x300..=0x3FF | `rsrcsrv`                        |
//! | 0x400..=0x4FF | `mm`                             |
//! | 0x500..=0x5FF | `vfs::public` (client-facing)    |
//! | 0x600..=0x6FF | `vfs::backend` (saltyfs / etc.)  |
//! | 0x700..=0x7FF | `log`                            |
//! | 0x800..=0x8FF | `netsrv`                         |
//! | n/a           | `correlation`, `common`, `posix`, `win32` |

#![no_std]

pub mod blk;
pub mod common;
pub mod console;
pub mod control;
pub mod correlation;
pub mod display;
pub mod init;
pub mod ldsrv;
pub mod log;
pub mod mm;
pub mod namesrv;
pub mod netsrv;
pub mod pci;
pub mod posix;
pub mod posix_abi;
pub mod rsrcsrv;
pub mod vfs;
pub mod win32;
