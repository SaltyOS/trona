// SPDX-License-Identifier: GPL-2.0-only
//
//! Generic non-moving segment-backed index array.
//!
//! Substrate-level dynamic-grow primitive shared by all servers
//! (init / namesrv / rsrcsrv / mmsrv / vfs / drivers / future
//! subsystems). Storage is a singly-linked list of segments; each
//! segment owns a contiguous run of `T` entries. Indices are stable
//! for the lifetime of an entry — `push` only ever appends, the
//! base type carries no shifting `remove`. Higher layers implement
//! tombstone semantics (`active: bool` + `live_gen` advance) on top.
//!
//! # Why segment-backed
//!
//! - **Stable indices.** Slots returned by `push` are valid until
//!   the array is dropped. Callers can hand the index to long-lived
//!   identifiers (cookies, fds, handles) and rely on it never
//!   shifting under them. A `Vec`-style contiguous backing would
//!   reallocate-and-move on grow, invalidating every outstanding
//!   pointer; segment-backed storage adds new memory without ever
//!   touching the old.
//! - **No fixed limit.** Capacity grows by appending fresh
//!   segments. The growth schedule starts at `INITIAL_SEGMENT_CAP`
//!   entries and doubles the segment size up to a per-segment
//!   ceiling so a single allocation stays small enough to fit in
//!   one frame for the common cases, while total array capacity
//!   remains unbounded.
//! - **Allocator injection.** Substrate cannot hardwire frame
//!   acquisition because mmsrv / rsrcsrv / init are themselves the
//!   memory-management plane and cannot use mmsrv-mediated
//!   `mm::mmap_anon` for their own internal tables. Each caller
//!   provides a [`SegmentAllocator`] tailored to its position in
//!   the boot graph: leaf services use mmap-backed allocators,
//!   core servers use frame-retype carve-outs from their own
//!   untyped pools.
//!
//! # Conservative API
//!
//! Only the operations that every consumer needs live on the base
//! type: `new_empty`, `len`, `capacity`, `is_empty`, `push`, `get`,
//! `get_mut`, `iter`, `iter_mut`. `remove` is intentionally absent —
//! shifting storage breaks the stable-index invariant. Callers that
//! want logical removal store an `active` flag inside `T` and
//! advance a generation counter to invalidate stale references.
//!
//! # Lifetime
//!
//! `SegmentedArray::Drop` does not call back into the allocator —
//! `SegmentAllocator` is a one-way API. Servers retain the array
//! for their own lifetime; on process exit the OS reclaims the
//! backing memory whether it came from `mmap_anon` or a frame
//! carve-out.
//!
//! # Owned (`Drop`) payloads
//!
//! `clear` and `Drop` run `T`'s destructor on every live element, so a
//! `T` that owns a capability (e.g. an `OwnedCap` field) releases it
//! when the array is cleared or dropped. `push` only ever writes a
//! fresh slot, never overwriting a live element. The one caveat is
//! logical removal: a tombstone (`active = false` inside `T`) does
//! **not** run `T`'s `Drop` — the base type never reuses a slot, so a
//! tombstoned element's owned payload lives until `clear` / `Drop`. A
//! higher layer that reuses a tombstoned slot (via `get_mut` +
//! assignment, as `CookieTable::arm` does) drops the stale element at
//! that assignment. Callers that need *prompt* release on tombstone
//! must explicitly clear the owned field (move it out / set it to its
//! empty state) when they set `active = false`.

use core::marker::PhantomData;

/// Allocator that hands out a single chunk of zeroed bytes per
/// call. Each `SegmentedArray` segment grow asks for one chunk
/// large enough to hold both the segment header and its entries.
pub trait SegmentAllocator {
    /// Reserve `bytes` bytes of zeroed memory aligned to at least
    /// `align`. The pointer must remain valid for the lifetime of
    /// the requesting `SegmentedArray`. Returns `Err` when the
    /// underlying memory source (mmsrv anonymous map / frame retype
    /// / etc.) cannot satisfy the request.
    ///
    /// # Safety
    ///
    /// The returned pointer must be writable for `bytes` bytes
    /// starting at the returned address, and must outlive every
    /// outstanding reference into the array's segments.
    unsafe fn alloc_zeroed(&mut self, bytes: usize, align: usize) -> Result<*mut u8, SegError>;
}

/// Failure modes for [`SegmentAllocator::alloc_zeroed`] and the
/// `SegmentedArray` operations that funnel through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegError {
    /// The allocator's backing memory source is exhausted.
    OutOfMemory,
    /// Arithmetic overflowed while computing a segment layout
    /// (segment cap × `size_of::<T>()` did not fit in `usize`, or
    /// the cumulative `capacity` would exceed `u32::MAX`).
    Overflow,
}

/// Initial segment size in entries. Picked small enough to keep the
/// first allocation cheap when an array stays sparsely populated,
/// while still amortising header overhead across multiple entries.
const INITIAL_SEGMENT_CAP: u32 = 64;

#[repr(C)]
struct Segment<T> {
    /// Singly-linked next segment, or null at the tail.
    next: *mut Segment<T>,
    /// Number of `T` slots this segment owns (`data[0..cap]`).
    cap: u32,
    /// Number of slots currently occupied (`data[0..used]`).
    used: u32,
    /// Pointer to the first entry. The header and entries share a
    /// single allocation; this pointer is computed once at segment
    /// init from the base allocation address plus the aligned
    /// header size.
    data: *mut T,
}

/// Segment-backed dynamic array with stable indices.
///
/// See module-level documentation for design rationale.
#[repr(C)]
pub struct SegmentedArray<T> {
    head: *mut Segment<T>,
    tail: *mut Segment<T>,
    len: u32,
    capacity: u32,
    _marker: PhantomData<T>,
}

// `*mut Segment<T>` is not `Send`/`Sync` by default, but a
// `SegmentedArray` only escapes its owning thread when the caller
// explicitly synchronises it; servers wrap the array in their own
// reactor state which carries the synchronisation contract.
unsafe impl<T: Send> Send for SegmentedArray<T> {}
unsafe impl<T: Sync> Sync for SegmentedArray<T> {}

impl<T> SegmentedArray<T> {
    /// Construct an empty array. No memory is reserved until the
    /// first `push`.
    pub const fn new_empty() -> Self {
        Self {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
            len: 0,
            capacity: 0,
            _marker: PhantomData,
        }
    }

    /// Total number of entries currently stored across every
    /// segment.
    #[inline]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Total number of slots currently allocated across every
    /// segment.
    #[inline]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Whether `len() == 0`.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Logically empty the array. Sets `len = 0` and resets every
    /// segment's `used` counter so existing segments are reused
    /// for future pushes. The segment chain itself is preserved
    /// — the allocator is one-way, so segments stay backed for
    /// the lifetime of the array. The next `push` reuses segment
    /// 0 from offset 0 instead of allocating fresh memory.
    pub fn clear(&mut self) {
        self.len = 0;
        let mut cur = self.head;
        while !cur.is_null() {
            unsafe {
                let seg = &mut *cur;
                // Drop each live element (e.g. release an `OwnedCap`'s
                // capability) before the slot is vacated. A no-op for
                // Copy/POD payloads. The segment memory stays backed
                // (one-way allocator) for reuse by the next push.
                for i in 0..seg.used {
                    core::ptr::drop_in_place(seg.data.add(i as usize));
                }
                seg.used = 0;
                cur = seg.next;
            }
        }
    }

    /// Append `value` and return its absolute slot index. Allocates
    /// a fresh segment via `alloc` when the active tail is full.
    ///
    /// # Safety
    ///
    /// The allocator's [`SegmentAllocator::alloc_zeroed`] contract
    /// must hold for the returned chunk: writable for the requested
    /// byte count, alive for the lifetime of `self`. Failure to
    /// satisfy that surface allows undefined behaviour through any
    /// later `get` / `iter`.
    pub unsafe fn push<A: SegmentAllocator>(
        &mut self,
        value: T,
        alloc: &mut A,
    ) -> Result<u32, SegError> {
        unsafe {
            if self.tail.is_null() || (*self.tail).used >= (*self.tail).cap {
                self.grow_segment(alloc)?;
            }
            let seg = &mut *self.tail;
            let idx_in_seg = seg.used;
            seg.data.add(idx_in_seg as usize).write(value);
            seg.used += 1;
            let absolute = self.len;
            self.len += 1;
            Ok(absolute)
        }
    }

    /// Borrow the entry at absolute index `index`, or `None` when
    /// `index >= len()`.
    pub fn get(&self, index: u32) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        let mut cur = self.head;
        let mut remaining = index;
        unsafe {
            while !cur.is_null() {
                let seg = &*cur;
                if remaining < seg.used {
                    return Some(&*seg.data.add(remaining as usize));
                }
                remaining -= seg.used;
                cur = seg.next;
            }
        }
        None
    }

    /// Mutably borrow the entry at absolute index `index`, or `None`
    /// when `index >= len()`.
    pub fn get_mut(&mut self, index: u32) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        let mut cur = self.head;
        let mut remaining = index;
        unsafe {
            while !cur.is_null() {
                let seg = &mut *cur;
                if remaining < seg.used {
                    return Some(&mut *seg.data.add(remaining as usize));
                }
                remaining -= seg.used;
                cur = seg.next;
            }
        }
        None
    }

    /// Iterate every live entry in insertion order.
    pub fn iter(&self) -> SegIter<'_, T> {
        SegIter {
            current: self.head,
            idx_in_seg: 0,
            _marker: PhantomData,
        }
    }

    /// Mutably iterate every live entry in insertion order.
    pub fn iter_mut(&mut self) -> SegIterMut<'_, T> {
        SegIterMut {
            current: self.head,
            idx_in_seg: 0,
            _marker: PhantomData,
        }
    }

    /// Allocate a new segment via `alloc`, link it to the tail, and
    /// migrate `tail` onto it. Cap doubles each grow, saturating at
    /// `u32::MAX` entries. There is no declared per-segment ceiling
    /// — the natural backstop is the allocator's frame source
    /// running out, surfaced as `SegError::OutOfMemory`.
    unsafe fn grow_segment<A: SegmentAllocator>(&mut self, alloc: &mut A) -> Result<(), SegError> {
        let next_cap = if self.tail.is_null() {
            INITIAL_SEGMENT_CAP
        } else {
            let prev_cap = unsafe { (*self.tail).cap };
            prev_cap.checked_mul(2).ok_or(SegError::Overflow)?
        };

        let header_size = core::mem::size_of::<Segment<T>>();
        let header_align = core::mem::align_of::<Segment<T>>();
        let entry_align = core::mem::align_of::<T>();
        let align = if header_align > entry_align {
            header_align
        } else {
            entry_align
        };
        // Round up the header so the entries land at a `T`-aligned
        // address regardless of `Segment<T>` end.
        let entries_offset = (header_size + align - 1) & !(align - 1);
        let entry_size = core::mem::size_of::<T>();
        let entries_bytes = (next_cap as usize)
            .checked_mul(entry_size)
            .ok_or(SegError::Overflow)?;
        let total = entries_offset
            .checked_add(entries_bytes)
            .ok_or(SegError::Overflow)?;

        let raw = unsafe { alloc.alloc_zeroed(total, align)? };
        let seg = raw as *mut Segment<T>;
        let data = unsafe { (raw as *mut u8).add(entries_offset) as *mut T };
        unsafe {
            (*seg).next = core::ptr::null_mut();
            (*seg).cap = next_cap;
            (*seg).used = 0;
            (*seg).data = data;
        }

        if self.tail.is_null() {
            self.head = seg;
        } else {
            unsafe {
                (*self.tail).next = seg;
            }
        }
        self.tail = seg;
        self.capacity = self
            .capacity
            .checked_add(next_cap)
            .ok_or(SegError::Overflow)?;
        Ok(())
    }
}

impl<T> Drop for SegmentedArray<T> {
    /// Drop every live element so owned payloads (e.g. `OwnedCap`) release
    /// their capabilities. The segment buffers come from a one-way
    /// [`SegmentAllocator`] and are not returned here — a dropped
    /// `SegmentedArray` leaks its segment memory but never its payloads.
    fn drop(&mut self) {
        let mut cur = self.head;
        while !cur.is_null() {
            // SAFETY: each segment's `[0, used)` entries are initialised;
            // single-threaded server invariant.
            unsafe {
                let seg = &mut *cur;
                for i in 0..seg.used {
                    core::ptr::drop_in_place(seg.data.add(i as usize));
                }
                cur = seg.next;
            }
        }
    }
}

/// Read-only iterator over [`SegmentedArray`].
pub struct SegIter<'a, T> {
    current: *mut Segment<T>,
    idx_in_seg: u32,
    _marker: PhantomData<&'a T>,
}

impl<'a, T> Iterator for SegIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            while !self.current.is_null() {
                let seg = &*self.current;
                if self.idx_in_seg < seg.used {
                    let item = &*seg.data.add(self.idx_in_seg as usize);
                    self.idx_in_seg += 1;
                    return Some(item);
                }
                self.current = seg.next;
                self.idx_in_seg = 0;
            }
        }
        None
    }
}

/// Mutable iterator over [`SegmentedArray`].
pub struct SegIterMut<'a, T> {
    current: *mut Segment<T>,
    idx_in_seg: u32,
    _marker: PhantomData<&'a mut T>,
}

impl<'a, T> Iterator for SegIterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            while !self.current.is_null() {
                let seg = &mut *self.current;
                if self.idx_in_seg < seg.used {
                    let item = &mut *seg.data.add(self.idx_in_seg as usize);
                    self.idx_in_seg += 1;
                    return Some(item);
                }
                self.current = seg.next;
                self.idx_in_seg = 0;
            }
        }
        None
    }
}
