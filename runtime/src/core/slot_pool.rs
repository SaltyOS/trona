//! Per-caller CSpace slot pool.
//!
//! `slot_alloc` is the process-wide slot allocator — seeded once at
//! spawn time and shared by every caller in the address space. When a
//! caller wants its own private slice, typically because it spawns
//! threads on a fixed reservation that must not contend with other
//! threads' spawns, it allocates a `SlotPool` over a contiguous range
//! of slots and passes it through `SpawnConfig::slot_pool`. The
//! `spawn_fn` reservation (TCB + SC + IPC frame, stack pages, TLS
//! pages) then comes out of that pool instead of the global allocator.
//!
//! Thread-safe (atomic bump). One-shot init: callers reserve a range
//! once in their internal slot map and call `SlotPool::init` exactly
//! once before any allocation. There is no free path — slots are
//! owned for the lifetime of the spawn.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU64, Ordering};

use trona_kernel::core_types::Cap;

/// Atomic bump allocator over a fixed range of CSpace slots. Used by
/// callers that need `spawn_fn` reservations isolated from the global
/// `slot_alloc` pool — for example, to keep a single `IpcTimer`'s
/// thread reservation safe from a worker pool's partial spawn.
pub struct SlotPool {
    base: AtomicU64,
    end: AtomicU64,
    next: AtomicU64,
}

impl SlotPool {
    /// Construct an empty pool. Must be `init`d before use; allocation
    /// returns `None` until then.
    pub const fn new() -> Self {
        Self {
            base: AtomicU64::new(0),
            end: AtomicU64::new(0),
            next: AtomicU64::new(0),
        }
    }

    /// Set the pool extent. Idempotent only when called with the same
    /// `(base, count)`; calling with a different range resets the
    /// cursor (callers are expected to call this once per process
    /// boot, before any `alloc_consecutive`).
    pub fn init(&self, base: Cap, count: u64) {
        self.base.store(base, Ordering::Release);
        self.end
            .store(base.saturating_add(count), Ordering::Release);
        self.next.store(base, Ordering::Release);
    }

    /// True after `init` has been called with a non-zero `count`.
    pub fn is_initialized(&self) -> bool {
        self.end.load(Ordering::Acquire) > self.base.load(Ordering::Acquire)
    }

    /// Allocate `n` consecutive slots. Returns `None` when the pool is
    /// exhausted, uninitialised, or `n == 0`.
    pub fn alloc_consecutive(&self, n: u64) -> Option<Cap> {
        if n == 0 {
            return None;
        }
        let end = self.end.load(Ordering::Acquire);
        if end == 0 {
            return None;
        }
        loop {
            let cur = self.next.load(Ordering::Acquire);
            let next = cur.checked_add(n)?;
            if next > end {
                return None;
            }
            if self
                .next
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(cur);
            }
        }
    }

    /// Number of slots still available in the pool. Approximate under
    /// concurrent allocation — strictly monotonic non-increasing.
    pub fn remaining(&self) -> u64 {
        let end = self.end.load(Ordering::Acquire);
        let cur = self.next.load(Ordering::Acquire);
        end.saturating_sub(cur)
    }
}

impl Default for SlotPool {
    fn default() -> Self {
        Self::new()
    }
}
