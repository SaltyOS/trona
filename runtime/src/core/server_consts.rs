// SPDX-License-Identifier: GPL-2.0-only
//
//! Server-policy constants consumed by libtrona substrate.
//!
//! Narrow subset of the historical `uapi::consts::server` table — only
//! entries that substrate itself reads. Other server-policy fields
//! (spawn flags, stdio modes, respawn discriminators, mmap backings,
//! network state machine) live with their owning userland server
//! crate.

/// Deterministic CNode root slots reserved for the substrate CSpace
/// expansion bridge. The runtime allocator keeps these slots free so
/// `slot_alloc::SlotAllocator` can fall back to them when the
/// per-process CSpace runs out of room.
pub const CSPACE_EXPAND_BASE: u64 = 1008;
pub const MAX_CSPACE_EXPANSIONS: usize = 64;
