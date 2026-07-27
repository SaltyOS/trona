// SPDX-License-Identifier: GPL-2.0-only
//
//! Page-backed slab + base-sorted index + stable-id machinery shared by
//! every server that needs growable, quota-managed, stable-index
//! storage carved from its own memory plane (mmsrv per-client region /
//! reservation tables; init's process table, lifecycle stream, and
//! extras arenas).
//!
//! # Why a second primitive next to [`SegmentedArray`](crate::SegmentedArray)
//!
//! [`SegmentedArray`](crate::SegmentedArray) is an append-only store
//! whose allocator never frees — it suits process-lifetime tables
//! (cookie tables) but not per-client storage that must be reclaimed on
//! teardown. This module adds three pieces with explicit, *threaded*
//! deallocation:
//!
//! * [`PageBacking`] — the allocate/free seam. Generic, not a trait
//!   object (`no_std`, no `dyn`): each server injects its own page
//!   source — mmsrv retypes a MemoryObject out of its untyped pool and
//!   self-maps it; init untyped-retypes. It is threaded as
//!   `&mut impl PageBacking` so the backing's own `&mut FrameAllocator`
//!   is never aliased by a `Drop` running behind the caller's back.
//! * [`TrackedSlab<T>`] — epoch-tagged slot store. A [`SlabId`]
//!   `(idx, epoch)` names a slot and its incarnation; a freed-then-reused
//!   slot bumps its epoch so stale handles miss deterministically. No
//!   ABA.
//! * [`BaseSortedIndex`] — a `(base, length) -> slot` lookup kept sorted
//!   by base for overlap / gap queries over the slab's entries.
//!
//! # No `Drop`-based freeing
//!
//! Neither the slab, the index, nor [`TrackedBuffer`] frees on `Drop`.
//! Freeing needs `&mut impl PageBacking`, which a `Drop` cannot obtain
//! without reaching hidden global state and aliasing the live
//! allocator (the exact double-free / aliasing hazard this design
//! avoids). Every owner therefore calls `release(&mut backing)` before
//! going out of scope; [`TrackedBuffer`] is non-`Copy` so a buffer
//! cannot be silently duplicated into a double-free, and is moved into
//! [`PageBacking::free_pages`] exactly once.
//!
//! # Owned (`Drop`) payloads vs. backing pages
//!
//! The "no `Drop`-based freeing" rule above is about the **backing
//! pages**, not the element payloads. [`TrackedSlab::slot_free`],
//! [`TrackedSlab::release`], and `Drop` all run `T`'s destructor on
//! every live slot, so a `T` that owns a capability (e.g. an
//! `OwnedCap` field) is released when its slot is freed or the slab is
//! torn down. `grow` relocates live slots by a bitwise move
//! (`copy_nonoverlapping` into the new buffer, then `free_pages` the
//! old buffer **without** dropping) — a correct move for any `T`, with
//! no double-free. An `OwnedCap` may therefore be embedded directly in
//! `T`; free it via [`TrackedSlab::slot_free`].

use core::marker::PhantomData;
use core::mem::MaybeUninit;
use uapi::KERNITE_PAGE_BYTES;

/// Page size in bytes, as `usize`. `uapi::KERNITE_PAGE_BYTES` is a
/// `u32`; every size computation below is in `usize`.
const PAGE_BYTES: usize = KERNITE_PAGE_BYTES as usize;

// ---------------------------------------------------------------------------
// TrackedBuffer + PageBacking
// ---------------------------------------------------------------------------

/// Owning handle to a run of `pages` contiguous pages that a
/// [`PageBacking`] allocated and mapped writable into its own address
/// space.
///
/// `token` is backing-defined provenance that the neutral machinery
/// never interprets — it only round-trips it back to
/// [`PageBacking::free_pages`]. mmsrv packs `[mo_cap_slot,
/// source_chunk_idx]`; init packs its own untyped-retype provenance.
///
/// Non-`Copy`, non-`Clone`, no `Drop`: the buffer is moved into
/// `free_pages` exactly once. Dropping it without freeing leaks its
/// pages (and, for an MO-backed buffer, leaves the MO child live so its
/// untyped chunk never resets) — every owner must `release` first.
pub struct TrackedBuffer {
    ptr: *mut u8,
    pages: u32,
    token: [u64; 2],
}

impl TrackedBuffer {
    /// The empty buffer: no pages, null pointer, zero token. Safe to
    /// pass to [`PageBacking::free_pages`] (a no-op) and to leave in a
    /// slab / index slot that currently owns no memory.
    pub const fn zeroed() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            pages: 0,
            token: [0; 2],
        }
    }

    /// Build a buffer from a backing's allocation result. Called only by
    /// a [`PageBacking`] implementation; the neutral machinery never
    /// fabricates a buffer.
    pub const fn new(ptr: *mut u8, pages: u32, token: [u64; 2]) -> Self {
        Self { ptr, pages, token }
    }

    /// First mapped byte of the run.
    #[inline]
    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Number of pages in the run.
    #[inline]
    pub fn pages(&self) -> u32 {
        self.pages
    }

    /// Backing-defined provenance token. Meaningful only to the
    /// [`PageBacking`] that produced this buffer.
    #[inline]
    pub fn token(&self) -> [u64; 2] {
        self.token
    }

    /// Whether this buffer owns no memory.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.pages == 0
    }
}

/// The allocate / free seam between the neutral slab machinery and a
/// server's private page source. Injected as `&mut impl PageBacking`.
///
/// # Single-threaded contract
///
/// Implementors and callers run on a single server thread (mmsrv's two
/// reactor TCBs serialise under `STATE_LOCK`; init's owner loop is
/// single-threaded). Both methods are `unsafe`: callers uphold that
/// invariant and the buffer-provenance rule below.
pub trait PageBacking {
    /// Allocate `pages` contiguous, **zeroed** pages mapped writable
    /// into the backing's address space. Returns `None` on memory
    /// exhaustion. The returned [`TrackedBuffer`] must be handed back to
    /// [`free_pages`](PageBacking::free_pages) on the same backing
    /// before it is dropped.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    unsafe fn alloc_pages(&mut self, pages: usize) -> Option<TrackedBuffer>;

    /// Reverse of [`alloc_pages`](PageBacking::alloc_pages): unmap the
    /// pages and release the backing kernel object(s). A no-op on
    /// [`TrackedBuffer::zeroed`].
    ///
    /// # Safety
    ///
    /// `buf` must have originated from `alloc_pages` on **this** backing
    /// and have no live references into its pages.
    unsafe fn free_pages(&mut self, buf: TrackedBuffer);
}

// ---------------------------------------------------------------------------
// SlabId
// ---------------------------------------------------------------------------

/// Stable handle to a [`TrackedSlab`] slot: `idx` names the slot,
/// `epoch` its incarnation. A handle into a freed-then-reused slot
/// deterministically misses because the slot's epoch advanced on free.
///
/// `INVALID` is the all-zero pattern, so a zero-initialised handle is
/// always invalid. mmsrv wraps this as `RegionId` / `ReservationId`;
/// init uses it directly as a process / extras handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct SlabId {
    pub idx: u32,
    pub epoch: u32,
}

impl SlabId {
    /// The reserved "no entry" handle. `idx == 0` is never a live slot.
    pub const INVALID: Self = Self { idx: 0, epoch: 0 };

    /// Whether this handle could name a live slot (non-sentinel index).
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.idx != 0
    }
}

// ---------------------------------------------------------------------------
// ReservationKind
// ---------------------------------------------------------------------------

/// Classification of a reserved VA range, shared as the wire
/// discriminant by `MM_RESERVE_RANGE` (init encodes, mmsrv decodes) and
/// as the gap-allocator avoidance tag.
///
/// Policy interpretation — whether a kind is inherited across `fork`,
/// whether it carries a stack-guard back-link, who owns it — lives with
/// the consuming server (mmsrv), not here. This enum is only the
/// discriminant and its `u64` wire codec.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ReservationKind {
    /// Owner-claimed VA arena filled lazily (init's proc-table,
    /// extras, and lifecycle arenas).
    Arena = 0,
    /// "No mapping ever" zone — a stack guard hole or the null guard.
    Guard = 1,
    /// VA the allocator must avoid with no specific owner (kernel half,
    /// ABI-fixed slots, externally-managed VA).
    Exclusion = 2,
    /// Per-process internal scratch — not inherited across `fork`.
    System = 3,
}

impl ReservationKind {
    /// Decode the wire value sent over `MM_RESERVE_RANGE`. Returns
    /// `None` for an unknown discriminant.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Arena),
            1 => Some(Self::Guard),
            2 => Some(Self::Exclusion),
            3 => Some(Self::System),
            _ => None,
        }
    }

    /// The byte discriminant.
    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// TrackedSlab
// ---------------------------------------------------------------------------

/// The reserved "no entry" slot index. Live slots start at 1.
const INVALID_INDEX: u32 = 0;

/// First usable slot index. Index 0 is the [`INVALID_INDEX`] sentinel;
/// live entries occupy `[1, high_water)`.
const FIRST_LIVE_INDEX: u32 = 1;

const SLOT_FREE: u8 = 0;
const SLOT_LIVE: u8 = 1;

/// Per-slot state inside a [`TrackedSlab`]. A `Live` slot carries the
/// payload; a `Free` slot links into the intrusive free list.
///
/// `epoch` starts at 1 and is bumped on every live↔free transition, so
/// a stale [`SlabId`] whose epoch no longer matches fails lookup.
#[repr(C)]
struct SlabSlot<T> {
    epoch: u32,
    state: u8,
    _pad: [u8; 3],
    next_free: u32,
    value: MaybeUninit<T>,
}

impl<T> SlabSlot<T> {
    const fn empty() -> Self {
        Self {
            epoch: 1,
            state: SLOT_FREE,
            _pad: [0; 3],
            next_free: 0,
            value: MaybeUninit::uninit(),
        }
    }
}

/// Generic slab backed by a single [`TrackedBuffer`] grown on demand
/// through an injected [`PageBacking`].
///
/// Slot 0 is the [`INVALID_INDEX`] sentinel and is never handed out.
/// Live slots occupy `[1, high_water)`; freed slots form an intrusive
/// free list rooted at `free_head`. `grow` reallocates a doubled buffer
/// and copies the live range, so each slab holds exactly one backing
/// buffer at a time and a [`SlabId`] stays valid for the lifetime of the
/// entry it names.
pub struct TrackedSlab<T> {
    buf: TrackedBuffer,
    ptr: *mut SlabSlot<T>,
    capacity: u32,
    /// One past the highest-ever-allocated slot. Starts at 1; only
    /// increases (freed slots return to `free_head`, not the tail).
    high_water: u32,
    /// Head of the intrusive free list, or 0 when empty.
    free_head: u32,
    /// Currently-live slot count.
    live_count: u32,
    _phantom: PhantomData<T>,
}

impl<T> TrackedSlab<T> {
    /// Empty slab with no backing buffer. The first `slot_alloc` /
    /// `reserve_slots` lazily allocates the starter buffer.
    pub const fn empty() -> Self {
        Self {
            buf: TrackedBuffer::zeroed(),
            ptr: core::ptr::null_mut(),
            capacity: 0,
            high_water: FIRST_LIVE_INDEX,
            free_head: 0,
            live_count: 0,
            _phantom: PhantomData,
        }
    }

    /// Number of currently-live slots.
    #[inline]
    pub fn len(&self) -> usize {
        self.live_count as usize
    }

    /// Whether the slab holds no live entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.live_count == 0
    }

    /// Ensure capacity for at least `additional` fresh slot allocations
    /// without changing the live set. Used by the transaction layer to
    /// make a subsequent publish infallible. Returns `false` on memory
    /// exhaustion.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn reserve_slots(
        &mut self,
        additional: u32,
        backing: &mut impl PageBacking,
    ) -> bool {
        unsafe {
            if additional == 0 {
                return true;
            }
            let Some(want_high_water) = self.high_water.checked_add(additional) else {
                return false;
            };
            while want_high_water > self.capacity {
                if !self.grow(backing) {
                    return false;
                }
            }
            true
        }
    }

    /// Epoch of the slot at `idx`, or 0 when the slot is empty or out of
    /// range. Lets a [`BaseSortedIndex`] (which stores only the bare
    /// slot index) reconstruct a full [`SlabId`] on demand.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn generation_at(&self, idx: u32) -> u32 {
        unsafe {
            if idx < FIRST_LIVE_INDEX || idx >= self.high_water {
                return 0;
            }
            (*self.ptr.add(idx as usize)).epoch
        }
    }

    /// Allocate a slot, write `value`, and return its [`SlabId`]. Reuses
    /// a freed slot if one exists, else grows. Returns `None` on memory
    /// exhaustion.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn slot_alloc(
        &mut self,
        value: T,
        backing: &mut impl PageBacking,
    ) -> Option<SlabId> {
        unsafe { self.slot_alloc_or_return(value, backing) }.ok()
    }

    /// Like [`slot_alloc`](Self::slot_alloc) but, on memory exhaustion (no
    /// free slot and a failed grow), returns the `value` back to the caller
    /// instead of dropping it — so a caller that must recover ownership of
    /// an owned payload (e.g. a region holding an `OwnedCap`) on failure
    /// can clean it up itself.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn slot_alloc_or_return(
        &mut self,
        value: T,
        backing: &mut impl PageBacking,
    ) -> Result<SlabId, T> {
        unsafe {
            if self.free_head != INVALID_INDEX {
                let idx = self.free_head;
                let slot = &mut *self.ptr.add(idx as usize);
                self.free_head = slot.next_free;
                slot.next_free = 0;
                slot.state = SLOT_LIVE;
                slot.value.write(value);
                self.live_count += 1;
                return Ok(SlabId {
                    idx,
                    epoch: slot.epoch,
                });
            }

            if self.high_water >= self.capacity && !self.grow(backing) {
                return Err(value);
            }
            let idx = self.high_water;
            self.high_water += 1;
            let slot = &mut *self.ptr.add(idx as usize);
            slot.state = SLOT_LIVE;
            slot.next_free = 0;
            slot.value.write(value);
            self.live_count += 1;
            Ok(SlabId {
                idx,
                epoch: slot.epoch,
            })
        }
    }

    /// Free the slot named by `id`, validating its epoch. Returns
    /// `false` when the handle is stale or out of range. Bumps the
    /// epoch so later lookups with the old handle miss.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn slot_free(&mut self, id: SlabId) -> bool {
        unsafe {
            if id.idx < FIRST_LIVE_INDEX || id.idx >= self.high_water {
                return false;
            }
            let slot = &mut *self.ptr.add(id.idx as usize);
            if slot.state != SLOT_LIVE || slot.epoch != id.epoch {
                return false;
            }
            slot.state = SLOT_FREE;
            // Drop the live value before clearing the slot — for an owned
            // payload (e.g. `OwnedCap`) this releases the underlying
            // capability. A no-op for Copy/POD payloads.
            core::ptr::drop_in_place(slot.value.as_mut_ptr());
            slot.value = MaybeUninit::uninit();
            slot.epoch = slot.epoch.wrapping_add(1);
            if slot.epoch == 0 {
                slot.epoch = 1;
            }
            slot.next_free = self.free_head;
            self.free_head = id.idx;
            self.live_count -= 1;
            true
        }
    }

    /// Shared reference to the live slot named by `id`, or `None` for a
    /// stale / out-of-range handle.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn slot_get(&self, id: SlabId) -> Option<&T> {
        unsafe {
            if id.idx < FIRST_LIVE_INDEX || id.idx >= self.high_water {
                return None;
            }
            let slot = &*self.ptr.add(id.idx as usize);
            if slot.state != SLOT_LIVE || slot.epoch != id.epoch {
                return None;
            }
            Some(&*slot.value.as_ptr())
        }
    }

    /// Mutable reference to the live slot named by `id`. Used for
    /// in-place updates inside a publication step.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn slot_get_mut(&mut self, id: SlabId) -> Option<&mut T> {
        unsafe {
            if id.idx < FIRST_LIVE_INDEX || id.idx >= self.high_water {
                return None;
            }
            let slot = &mut *self.ptr.add(id.idx as usize);
            if slot.state != SLOT_LIVE || slot.epoch != id.epoch {
                return None;
            }
            Some(&mut *slot.value.as_mut_ptr())
        }
    }

    /// Iterate `(SlabId, &T)` over every live slot in ascending index
    /// order, skipping freed slots.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn iter(&self) -> SlabIter<'_, T> {
        SlabIter {
            slab: self,
            cursor: FIRST_LIVE_INDEX,
        }
    }

    /// Iterate `(SlabId, &mut T)` over every live slot in ascending
    /// index order, skipping freed slots. Borrows the slab mutably for
    /// the iterator's lifetime, so no grow can invalidate `ptr` mid-walk.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn iter_mut(&mut self) -> SlabIterMut<'_, T> {
        SlabIterMut {
            ptr: self.ptr,
            cursor: FIRST_LIVE_INDEX,
            high_water: self.high_water,
            _phantom: PhantomData,
        }
    }

    /// Release the backing buffer and reset to the empty state,
    /// invalidating every previously-issued [`SlabId`].
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant. No live references into the
    /// slab may remain.
    pub unsafe fn release(&mut self, backing: &mut impl PageBacking) {
        unsafe {
            // Drop every live slot's value (e.g. release each `OwnedCap`'s
            // capability) before the backing memory is reclaimed.
            if !self.ptr.is_null() {
                for idx in FIRST_LIVE_INDEX..self.high_water {
                    let slot = &mut *self.ptr.add(idx as usize);
                    if slot.state == SLOT_LIVE {
                        core::ptr::drop_in_place(slot.value.as_mut_ptr());
                    }
                }
            }
            let buf = core::mem::replace(&mut self.buf, TrackedBuffer::zeroed());
            backing.free_pages(buf);
            self.ptr = core::ptr::null_mut();
            self.capacity = 0;
            self.high_water = FIRST_LIVE_INDEX;
            self.free_head = 0;
            self.live_count = 0;
        }
    }

    /// Grow the backing buffer to fit at least one more slot. Doubles
    /// capacity (or seeds it at one page worth of slots). Returns
    /// `false` on memory exhaustion, leaving the slab unchanged.
    unsafe fn grow(&mut self, backing: &mut impl PageBacking) -> bool {
        unsafe {
            let slot_size = core::mem::size_of::<SlabSlot<T>>();
            let new_cap = if self.capacity == 0 {
                (PAGE_BYTES / slot_size).max(8) as u32
            } else {
                self.capacity.saturating_mul(2)
            };
            let Some(total_bytes) = (new_cap as usize).checked_mul(slot_size) else {
                return false;
            };
            let pages = total_bytes.div_ceil(PAGE_BYTES);
            let Some(new_buf) = backing.alloc_pages(pages) else {
                return false;
            };
            let new_ptr = new_buf.ptr() as *mut SlabSlot<T>;
            // Pages arrive zeroed; stamp the empty (epoch-1, free)
            // pattern so freshly-grown tail slots behave like fresh
            // entries rather than zero-epoch ghosts.
            for i in 0..new_cap {
                core::ptr::write(new_ptr.add(i as usize), SlabSlot::<T>::empty());
            }
            // Copy the live range over the stamped tail (indices
            // [capacity, new_cap) keep their empty pattern).
            if self.capacity != 0 {
                core::ptr::copy_nonoverlapping(
                    self.ptr as *const u8,
                    new_ptr as *mut u8,
                    self.capacity as usize * slot_size,
                );
            }
            let old = core::mem::replace(&mut self.buf, new_buf);
            backing.free_pages(old);
            self.ptr = new_ptr;
            self.capacity = new_cap;
            true
        }
    }
}

impl<T> Drop for TrackedSlab<T> {
    /// Best-effort teardown when a slab is dropped without an explicit
    /// [`TrackedSlab::release`]: drop each live slot's value so owned
    /// payloads (e.g. `OwnedCap`) release their capabilities. The backing
    /// pages are reclaimed only by `release` (which is handed the
    /// `PageBacking`); a slab dropped in place leaks its pages but never
    /// its payloads. After `release` this is a no-op (`ptr` is null).
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        // SAFETY: single-threaded server invariant; `ptr` covers
        // `[0, capacity)` and every `SLOT_LIVE` slot holds an initialised T.
        unsafe {
            for idx in FIRST_LIVE_INDEX..self.high_water {
                let slot = &mut *self.ptr.add(idx as usize);
                if slot.state == SLOT_LIVE {
                    core::ptr::drop_in_place(slot.value.as_mut_ptr());
                }
            }
        }
    }
}

/// Iterator over the live `(SlabId, &T)` entries of a [`TrackedSlab`].
pub struct SlabIter<'a, T> {
    slab: &'a TrackedSlab<T>,
    cursor: u32,
}

impl<'a, T> Iterator for SlabIter<'a, T> {
    type Item = (SlabId, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            while self.cursor < self.slab.high_water {
                let idx = self.cursor;
                self.cursor += 1;
                let slot = &*self.slab.ptr.add(idx as usize);
                if slot.state == SLOT_LIVE {
                    return Some((
                        SlabId {
                            idx,
                            epoch: slot.epoch,
                        },
                        &*slot.value.as_ptr(),
                    ));
                }
            }
            None
        }
    }
}

/// Mutable iterator over the live `(SlabId, &mut T)` entries of a
/// [`TrackedSlab`]. Holds a raw slot pointer plus the `high_water`
/// snapshot taken when the `&mut` borrow was issued; that borrow pins
/// both (no grow can run) for the iterator's lifetime, so each yielded
/// reference names a distinct live slot and never aliases.
pub struct SlabIterMut<'a, T> {
    ptr: *mut SlabSlot<T>,
    cursor: u32,
    high_water: u32,
    _phantom: PhantomData<&'a mut T>,
}

impl<'a, T> Iterator for SlabIterMut<'a, T> {
    type Item = (SlabId, &'a mut T);

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            while self.cursor < self.high_water {
                let idx = self.cursor;
                self.cursor += 1;
                let slot = &mut *self.ptr.add(idx as usize);
                if slot.state == SLOT_LIVE {
                    return Some((
                        SlabId {
                            idx,
                            epoch: slot.epoch,
                        },
                        &mut *slot.value.as_mut_ptr(),
                    ));
                }
            }
            None
        }
    }
}

// ---------------------------------------------------------------------------
// BaseSortedIndex
// ---------------------------------------------------------------------------

/// One `(base, length) -> slot` entry of a [`BaseSortedIndex`]. `base`
/// and `length` are duplicated from the slab record so overlap / gap
/// scans never indirect through the slab; the bare slot index resolves
/// to a full [`SlabId`] via [`TrackedSlab::generation_at`] on demand.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndexEntry {
    pub base: u64,
    pub length: u64,
    pub slot: u32,
    pub _pad: u32,
}

/// Lookup index over a [`TrackedSlab`]'s slots, sorted by entry base VA
/// and backed by its own [`TrackedBuffer`]. Per-client interval counts
/// stay small (well under a few hundred), so an in-place shift on
/// insert / remove beats an interval tree.
pub struct BaseSortedIndex {
    buf: TrackedBuffer,
    ptr: *mut IndexEntry,
    capacity: u32,
    len: u32,
}

impl BaseSortedIndex {
    /// Empty index with no backing buffer.
    pub const fn empty() -> Self {
        Self {
            buf: TrackedBuffer::zeroed(),
            ptr: core::ptr::null_mut(),
            capacity: 0,
            len: 0,
        }
    }

    /// Number of entries currently indexed.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the index holds no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Entry count as `u32`.
    #[inline]
    pub fn count(&self) -> u32 {
        self.len
    }

    /// Ensure capacity for `additional` future inserts without changing
    /// the current contents. Returns `false` on memory exhaustion.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn reserve_entries(
        &mut self,
        additional: u32,
        backing: &mut impl PageBacking,
    ) -> bool {
        unsafe {
            let Some(want) = self.len.checked_add(additional) else {
                return false;
            };
            self.ensure_capacity(want, backing)
        }
    }

    /// Insert `(base, length, slot)` keeping the array sorted by `base`.
    /// Returns `false` on memory exhaustion (caller treats as OOM).
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn insert(
        &mut self,
        base: u64,
        length: u64,
        slot: u32,
        backing: &mut impl PageBacking,
    ) -> bool {
        unsafe {
            if !self.ensure_capacity(self.len + 1, backing) {
                return false;
            }
            let entries = self.ptr;
            let mut pos = 0u32;
            while pos < self.len {
                if (*entries.add(pos as usize)).base >= base {
                    break;
                }
                pos += 1;
            }
            if pos < self.len {
                core::ptr::copy(
                    entries.add(pos as usize),
                    entries.add(pos as usize + 1),
                    (self.len - pos) as usize,
                );
            }
            core::ptr::write(
                entries.add(pos as usize),
                IndexEntry {
                    base,
                    length,
                    slot,
                    _pad: 0,
                },
            );
            self.len += 1;
            true
        }
    }

    /// Remove the entry whose `slot` matches. Returns `true` if found.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn remove_slot(&mut self, slot: u32) -> bool {
        unsafe {
            let entries = self.ptr;
            for pos in 0..self.len {
                if (*entries.add(pos as usize)).slot == slot {
                    if pos + 1 < self.len {
                        core::ptr::copy(
                            entries.add(pos as usize + 1),
                            entries.add(pos as usize),
                            (self.len - pos - 1) as usize,
                        );
                    }
                    self.len -= 1;
                    return true;
                }
            }
            false
        }
    }

    /// Slot index of the first entry whose `[base, base + length)`
    /// overlaps the query range, or `None`. Linear scan — fine at the
    /// small per-client counts this index holds.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn first_overlap(&self, base: u64, length: u64) -> Option<u32> {
        unsafe {
            if self.len == 0 || length == 0 {
                return None;
            }
            let end = base.checked_add(length)?;
            let entries = self.ptr;
            for pos in 0..self.len {
                let e = &*entries.add(pos as usize);
                if e.base >= end {
                    return None;
                }
                let e_end = e.base.saturating_add(e.length);
                if e_end > base {
                    return Some(e.slot);
                }
            }
            None
        }
    }

    /// Read the entry at position `pos` (insertion-sorted order), or
    /// `None` if out of range.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn at(&self, pos: u32) -> Option<IndexEntry> {
        unsafe {
            if pos >= self.len {
                return None;
            }
            Some(*self.ptr.add(pos as usize))
        }
    }

    /// Iterate every `IndexEntry` in ascending base order.
    ///
    /// # Safety
    ///
    /// Single-threaded server invariant.
    pub unsafe fn iter(&self) -> IndexIter<'_> {
        IndexIter {
            ptr: self.ptr,
            len: self.len,
            cursor: 0,
            _phantom: PhantomData,
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
            backing.free_pages(buf);
            self.ptr = core::ptr::null_mut();
            self.capacity = 0;
            self.len = 0;
        }
    }

    unsafe fn ensure_capacity(&mut self, want: u32, backing: &mut impl PageBacking) -> bool {
        unsafe {
            if want <= self.capacity {
                return true;
            }
            let entry_size = core::mem::size_of::<IndexEntry>();
            let new_cap = if self.capacity == 0 {
                ((PAGE_BYTES / entry_size) as u32).max(want)
            } else {
                self.capacity.saturating_mul(2).max(want)
            };
            let Some(total) = (new_cap as usize).checked_mul(entry_size) else {
                return false;
            };
            let pages = total.div_ceil(PAGE_BYTES);
            let Some(new_buf) = backing.alloc_pages(pages) else {
                return false;
            };
            let new_ptr = new_buf.ptr() as *mut IndexEntry;
            if self.len > 0 {
                core::ptr::copy_nonoverlapping(self.ptr, new_ptr, self.len as usize);
            }
            let old = core::mem::replace(&mut self.buf, new_buf);
            backing.free_pages(old);
            self.ptr = new_ptr;
            self.capacity = new_cap;
            true
        }
    }
}

/// Iterator over the entries of a [`BaseSortedIndex`].
pub struct IndexIter<'a> {
    ptr: *const IndexEntry,
    len: u32,
    cursor: u32,
    _phantom: PhantomData<&'a IndexEntry>,
}

impl<'a> Iterator for IndexIter<'a> {
    type Item = IndexEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.len {
            return None;
        }
        unsafe {
            let entry = *self.ptr.add(self.cursor as usize);
            self.cursor += 1;
            Some(entry)
        }
    }
}
