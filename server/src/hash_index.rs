// SPDX-License-Identifier: GPL-2.0-only
//
//! `U32HashIndex` — a growable, `#![no_std]`, heap-free `u32 → u32`
//! index backed by a [`PageBacking`] page run. The O(1) companion to
//! the O(log/linear) [`BaseSortedIndex`](crate::slab::BaseSortedIndex):
//! where that one answers range-overlap queries over a small sorted set,
//! this answers exact-key lookups over an unbounded, churning key space
//! (init's `client_id → pid` map, which the fault dispatcher resolves
//! on every unhandled fault).
//!
//! # Design
//!
//! Open addressing with linear probing and **backward-shift deletion**
//! (Knuth 6.4 Algorithm R). Tombstones are avoided deliberately: a
//! long-lived table under steady insert/remove churn (process
//! spawn/exit) would accumulate dead tombstone slots and lengthen every
//! probe chain; backshift keeps chains tight and is itself
//! allocation-free.
//!
//! Keys are scattered with a Fibonacci multiplicative hash so that the
//! dense, monotonically-increasing `client_id` space does not pile into
//! one primary cluster.
//!
//! Capacity is always a power of two (page count doubles on grow, and
//! `PAGE_BYTES / size_of::<Entry>()` is itself a power of two), so the
//! Fibonacci bucket reduces to a single shift.
//!
//! # Key 0 is reserved
//!
//! [`EMPTY_KEY`] (`0`) marks an unused slot, so callers must not insert
//! key `0`. Init's `client_id`s and `pid`s are both `>= 1`, so this is
//! free.

use crate::slab::{PageBacking, TrackedBuffer};
use uapi::KERNITE_PAGE_BYTES;

/// Reserved empty-slot sentinel. Callers must never insert this key.
pub const EMPTY_KEY: u32 = 0;

/// 2^32 / golden ratio — the Fibonacci hashing multiplier.
const FIB_MUL: u32 = 0x9E37_79B1;

/// Grow when `len * 10 >= capacity * LOAD_NUM` (load factor 0.7).
const LOAD_NUM: u32 = 7;

#[derive(Clone, Copy)]
struct Entry {
    key: u32,
    val: u32,
}

impl Entry {
    const EMPTY: Self = Self {
        key: EMPTY_KEY,
        val: 0,
    };
}

const ENTRIES_PER_PAGE: u32 = KERNITE_PAGE_BYTES as u32 / core::mem::size_of::<Entry>() as u32;

pub struct U32HashIndex {
    buf: TrackedBuffer,
    entries: *mut Entry,
    /// Power-of-two slot count, or 0 before the first insert.
    capacity: u32,
    len: u32,
}

impl U32HashIndex {
    pub const fn empty() -> Self {
        Self {
            buf: TrackedBuffer::zeroed(),
            entries: core::ptr::null_mut(),
            capacity: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Home bucket for `key` under the current capacity (power of two).
    #[inline]
    fn bucket(&self, key: u32) -> u32 {
        // capacity is 2^n; the high n bits of the Fibonacci product give
        // a well-scattered index in `[0, capacity)`.
        let shift = 32 - self.capacity.trailing_zeros();
        (key.wrapping_mul(FIB_MUL)) >> shift
    }

    /// Whether `home` lies in the cyclic interval `(lo, hi]` — the test
    /// that decides if a probe-displaced entry must stay put during
    /// backshift deletion.
    #[inline]
    fn cyclic_in(home: u32, lo: u32, hi: u32) -> bool {
        if lo <= hi {
            home > lo && home <= hi
        } else {
            home > lo || home <= hi
        }
    }

    /// Look up `key`. Returns the value by copy so the caller can drop
    /// the borrow on this index before borrowing the table it points
    /// into. Returns `None` for the reserved [`EMPTY_KEY`].
    pub fn get(&self, key: u32) -> Option<u32> {
        if key == EMPTY_KEY || self.capacity == 0 {
            return None;
        }
        let mask = self.capacity - 1;
        let mut pos = self.bucket(key);
        for _ in 0..self.capacity {
            // SAFETY: `pos < capacity`, `entries` covers `capacity` slots.
            let e = unsafe { *self.entries.add(pos as usize) };
            if e.key == EMPTY_KEY {
                return None;
            }
            if e.key == key {
                return Some(e.val);
            }
            pos = (pos + 1) & mask;
        }
        None
    }

    /// Insert or overwrite `key → val`. Grows (and rehashes) when the
    /// load factor is exceeded. Returns `false` only on backing-store
    /// exhaustion. Inserting [`EMPTY_KEY`] is rejected (`false`).
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant; `backing` must be live.
    pub unsafe fn insert(&mut self, key: u32, val: u32, backing: &mut impl PageBacking) -> bool {
        if key == EMPTY_KEY {
            return false;
        }
        unsafe {
            // Overwrite-in-place does not change `len`, so only a fresh
            // insert needs headroom — but checking before the probe keeps
            // the grow/rehash off the hot lookup path.
            if self.capacity == 0 || (self.len + 1) * 10 >= self.capacity * LOAD_NUM {
                if !self.grow(backing) {
                    // A pure overwrite can still proceed at the old size.
                    if self.capacity == 0 || !self.has_key(key) {
                        return false;
                    }
                }
            }
            let mask = self.capacity - 1;
            let mut pos = self.bucket(key);
            loop {
                let slot = self.entries.add(pos as usize);
                if (*slot).key == EMPTY_KEY {
                    *slot = Entry { key, val };
                    self.len += 1;
                    return true;
                }
                if (*slot).key == key {
                    (*slot).val = val;
                    return true;
                }
                pos = (pos + 1) & mask;
            }
        }
    }

    /// Remove `key`, backward-shifting its probe chain so no gap breaks a
    /// later key's lookup. Returns `true` if the key was present.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn remove(&mut self, key: u32) -> bool {
        if key == EMPTY_KEY || self.capacity == 0 {
            return false;
        }
        unsafe {
            let mask = self.capacity - 1;
            let mut pos = self.bucket(key);
            let mut found = false;
            for _ in 0..self.capacity {
                let e = *self.entries.add(pos as usize);
                if e.key == EMPTY_KEY {
                    break;
                }
                if e.key == key {
                    found = true;
                    break;
                }
                pos = (pos + 1) & mask;
            }
            if !found {
                return false;
            }
            // Backward-shift: pull later entries into the gap when doing
            // so does not move them before their own home bucket.
            let mut gap = pos;
            let mut scan = (pos + 1) & mask;
            loop {
                let e = *self.entries.add(scan as usize);
                if e.key == EMPTY_KEY {
                    break;
                }
                let home = self.bucket(e.key);
                if !Self::cyclic_in(home, gap, scan) {
                    *self.entries.add(gap as usize) = e;
                    gap = scan;
                }
                scan = (scan + 1) & mask;
            }
            *self.entries.add(gap as usize) = Entry::EMPTY;
            self.len -= 1;
            true
        }
    }

    fn has_key(&self, key: u32) -> bool {
        self.get(key).is_some()
    }

    /// Double the table (or seed the first page) and rehash live entries
    /// into the new buffer. Returns `false` on backing exhaustion,
    /// leaving the old table intact.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant; `backing` must be live.
    unsafe fn grow(&mut self, backing: &mut impl PageBacking) -> bool {
        unsafe {
            let old_pages = self.buf.pages();
            let new_pages = if old_pages == 0 { 1 } else { old_pages * 2 };
            let Some(new_buf) = backing.alloc_pages(new_pages as usize) else {
                return false;
            };
            let new_entries = new_buf.ptr() as *mut Entry;
            let new_capacity = new_pages * ENTRIES_PER_PAGE;
            for i in 0..new_capacity {
                core::ptr::write(new_entries.add(i as usize), Entry::EMPTY);
            }

            let old_entries = self.entries;
            let old_capacity = self.capacity;
            let old_buf = core::mem::replace(&mut self.buf, new_buf);
            self.entries = new_entries;
            self.capacity = new_capacity;
            // `len` is preserved; re-probe each live key into the new map.
            let new_mask = new_capacity - 1;
            for i in 0..old_capacity {
                let e = *old_entries.add(i as usize);
                if e.key == EMPTY_KEY {
                    continue;
                }
                let mut pos = self.bucket(e.key);
                loop {
                    let slot = self.entries.add(pos as usize);
                    if (*slot).key == EMPTY_KEY {
                        *slot = e;
                        break;
                    }
                    pos = (pos + 1) & new_mask;
                }
            }

            if old_capacity != 0 {
                backing.free_pages(old_buf);
            }
            true
        }
    }

    /// Release the backing buffer and reset to empty.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant. No live references may remain.
    pub unsafe fn release(&mut self, backing: &mut impl PageBacking) {
        unsafe {
            let buf = core::mem::replace(&mut self.buf, TrackedBuffer::zeroed());
            if !buf.is_empty() {
                backing.free_pages(buf);
            }
            self.entries = core::ptr::null_mut();
            self.capacity = 0;
            self.len = 0;
        }
    }
}
