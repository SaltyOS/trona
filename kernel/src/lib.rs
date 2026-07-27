// SPDX-License-Identifier: GPL-2.0-only
//
//! trona_kernel — thin kernel ABI wrapper.
//!
//! Raw `KERNITE_SYS_INVOKE` syscall entry, capability invoke
//! wrappers, MessagePipe IPC primitives, IPC-buffer accessors, and
//! the kernel ABI shapes (`Cap / TronaResult / TronaMsg /
//! IpcContext / SaltyOSStartup* / SaltyOSCspaceLayoutV1 /
//! SaltyOSCapTable* / TronaRuntimeV1 / RtldDlfcnV1 /
//! ThreadLocalBlock`) that ride on it.
//!
//! Strict layering: this crate depends only on `uapi`. It knows
//! nothing about `namesrv`, `vfs`, `mmsrv`, `rsrcsrv`, or process
//! runtime — slot allocator, lazy lookup, weak cap symbols, TLS,
//! and reply endpoint lease helpers all live downstream in
//! `trona_runtime` / `trona_server`.
//!
//! Any kernel ABI wrapper that would have to consult slot-allocator
//! state (`cnode_copy / cnode_mint / cnode_move / cnode_mutate /
//! cnode_delete / cnode_revoke`), unmint a server-protocol label
//! (`mmsrv_*`, `MM_*`), or read a userland-defined struct shape
//! (`TronaVSpaceMemStats`, `TronaSysMemInfo`) is exposed here only
//! in its raw / depth-explicit / pointer-only form. Typed wrappers
//! live in the dependent crates.

#![no_std]
#![allow(clippy::missing_safety_doc)]

pub mod bootinfo;
pub mod core_types;
pub mod invoke;
pub mod ipc;
pub mod ipc_buffer;
pub mod syscall;

pub use core_types::{Cap, IpcContext, TronaMsg, TronaResult};
pub use uapi;
