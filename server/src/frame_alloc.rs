// SPDX-License-Identifier: GPL-2.0-only
//
//! Untyped-backed child allocator shared by every server that carves
//! kernel objects from its own adopted untyped chunks — mmsrv's frame /
//! MO / Watch / cookie-table supply, and init's slab page-backing.
//! FRAME / MO / Watch / etc. classes all retype from the same chunk
//! pool and keep `children_live` accurate so an exhausted chunk recycles
//! once every child cap has been revoked.
//!
//! Process-agnostic: every kernel call targets the caller's own CSpace
//! (`KERNITE_CAP_SELF_CSPACE`) and its own adopted untyped caps, so a
//! single definition serves any server. Each server holds its own
//! instance adopting its own untyped chunks.

use uapi::{
    KERNITE_CAP_SELF_CSPACE, KERNITE_INV_CNODE_REVOKE, KERNITE_INV_UNTYPED_RESET,
    KERNITE_INV_UNTYPED_RETYPE, KERNITE_OBJ_FRAME,
};

pub const MAX_CHUNKS: usize = 16;

#[derive(Clone, Copy)]
pub struct Chunk {
    pub cap: u64,
    pub size_bits: u8,
    pub children_live: u32,
    pub active: u8,
}

impl Chunk {
    const fn empty() -> Self {
        Self {
            cap: 0,
            size_bits: 0,
            children_live: 0,
            active: 0,
        }
    }
}

pub struct FrameAllocator {
    chunks: [Chunk; MAX_CHUNKS],
    high_watermark_bytes: u64,
    committed_pages: u64,
}

impl FrameAllocator {
    pub const fn new() -> Self {
        Self {
            chunks: [Chunk::empty(); MAX_CHUNKS],
            high_watermark_bytes: 0,
            committed_pages: 0,
        }
    }

    pub fn adopt(&mut self, cap: u64, size_bits: u8) -> bool {
        for chunk in self.chunks.iter_mut() {
            if chunk.active == 0 {
                chunk.cap = cap;
                chunk.size_bits = size_bits;
                chunk.children_live = 0;
                chunk.active = 1;
                self.high_watermark_bytes =
                    self.high_watermark_bytes.saturating_add(1u64 << size_bits);
                return true;
            }
        }
        false
    }

    /// Retype one child object into `dest_slot`. Returns the source
    /// chunk index on success, `None` on pool exhaustion.
    pub fn retype_child(&mut self, obj_type: u64, size_bits: u64, dest_slot: u64) -> Option<usize> {
        for pass in 0..2 {
            for idx in 0..MAX_CHUNKS {
                let chunk = &self.chunks[idx];
                if chunk.active == 0 {
                    continue;
                }
                if (chunk.size_bits as u64) < 12 {
                    continue;
                }
                let r = trona_kernel::syscall::invoke(
                    chunk.cap,
                    KERNITE_INV_UNTYPED_RETYPE as u64,
                    obj_type,
                    size_bits,
                    dest_slot,
                    0,
                );
                if r.error == 0 {
                    self.chunks[idx].children_live += 1;
                    return Some(idx);
                }
            }
            if pass == 0 {
                self.drain_and_reset();
            }
        }
        None
    }

    /// Retype one FRAME into `dest_slot`. Returns the chunk index on
    /// success, `None` on pool exhaustion.
    pub fn alloc_frame(&mut self, dest_slot: u64) -> Option<usize> {
        let idx = self.retype_child(KERNITE_OBJ_FRAME as u64, 12, dest_slot)?;
        self.committed_pages += 1;
        Some(idx)
    }

    pub fn release_child(&mut self, cap_slot: u64, chunk_idx: usize) {
        let _ = trona_kernel::syscall::invoke(
            KERNITE_CAP_SELF_CSPACE as u64,
            KERNITE_INV_CNODE_REVOKE as u64,
            cap_slot,
            0,
            0,
            0,
        );
        if chunk_idx >= MAX_CHUNKS {
            return;
        }
        let chunk = &mut self.chunks[chunk_idx];
        if chunk.active == 0 || chunk.children_live == 0 {
            return;
        }
        chunk.children_live -= 1;
        if chunk.children_live == 0 {
            let _ = trona_kernel::syscall::invoke(
                chunk.cap,
                KERNITE_INV_UNTYPED_RESET as u64,
                0,
                0,
                0,
                0,
            );
        }
    }

    pub fn drain_and_reset(&mut self) {
        for chunk in self.chunks.iter_mut() {
            if chunk.active == 0 || chunk.children_live != 0 {
                continue;
            }
            let _ = trona_kernel::syscall::invoke(
                chunk.cap,
                KERNITE_INV_UNTYPED_RESET as u64,
                0,
                0,
                0,
                0,
            );
        }
    }

    /// Number of adopted untyped chunks (active or not). Used by
    /// non-frame retype paths (Watch slab) to walk the pool.
    pub fn chunk_count(&self) -> usize {
        MAX_CHUNKS
    }

    /// Cap of the i-th untyped chunk if active, else `None`.
    pub fn chunk_cap(&self, idx: usize) -> Option<u64> {
        let chunk = self.chunks.get(idx)?;
        if chunk.active == 0 || chunk.cap == 0 {
            None
        } else {
            Some(chunk.cap)
        }
    }

    /// Increment the typed-child counter for chunk `idx`. Non-frame
    /// retypes (Watch / Timer / etc.) call this so a later reset stays
    /// accurate.
    pub fn note_typed_child(&mut self, idx: usize) {
        if let Some(chunk) = self.chunks.get_mut(idx) {
            if chunk.active != 0 {
                chunk.children_live = chunk.children_live.saturating_add(1);
            }
        }
    }

    pub fn high_watermark_bytes(&self) -> u64 {
        self.high_watermark_bytes
    }
}
