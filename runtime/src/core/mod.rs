// SPDX-License-Identifier: GPL-2.0-only
//
//! Process runtime core — slot allocator, IPC layer-reversal
//! wrappers, IPC timer, server-side primitive bridges.

pub mod ipc_ext;
pub mod ipc_timer;
pub mod server_consts;
pub mod slot_alloc;
pub mod slot_pool;
