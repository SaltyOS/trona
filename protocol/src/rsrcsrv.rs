// SPDX-License-Identifier: GPL-2.0-only
//
//! rsrcsrv server wire (block 0x300..=0x3FF). Resource allocator
//! routes every kernel-object retype through this label —
//! `trona_runtime::core::slot_alloc` is the canonical caller.

pub const RSRC_ALLOC: u64 = 0x300;
