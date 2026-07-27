// SPDX-License-Identifier: GPL-2.0-only
//
//! `ContinuationArena<C>` — token-keyed store of suspended async
//! continuations.
//!
//! When a single-threaded reactor must make a cross-server request
//! without blocking, it issues the request as a non-blocking
//! `MP_WRITE` stamped with a correlation token, parks the state needed
//! to finish the operation in this arena keyed by that token, and
//! returns to its event loop. When the peer's reply arrives — a
//! reply-marked `MP_WRITE` echoing the token, surfaced to the reactor
//! as a readable event — the dispatcher looks the token up here, takes
//! the parked continuation, and runs it to completion.
//!
//! This is the storage half of the async-call foundation. The
//! correlation *token* is opaque to the arena: an edge that rides the
//! kernel's reply-marked `MP_WRITE` path uses the kernel `mp_txid`; an
//! edge that carries its own application-level correlation header uses
//! whatever token that header encodes. The arena only maps `token ->
//! C` and owns the slot lifecycle.
//!
//! # Token discipline
//!
//! [`ContinuationArena::alloc_token`] hands out a monotonic token that
//! is always non-zero and always has bit 63 clear. The kernel reserves
//! bit 63 for *synchronous* `MP_CALL` transaction ids (the txid range
//! split): a sync-call reply carries a high-range txid, an async
//! continuation token a low-range one, so a token stamped here can
//! ride a reply-marked `MP_WRITE` without ever colliding with a kernel
//! sync-call reply on the same pipe. `0` is the reserved
//! "no correlation" sentinel and is never handed out.
//!
//! # ABA safety
//!
//! Slots are reused once a continuation is taken. A [`ContHandle`]
//! pins both the slot index and an epoch; the epoch is bumped on every
//! take, so a handle held across a take-and-reuse resolves to `None`
//! instead of aliasing the new occupant. A *token* is single-use by
//! construction (monotonic allocation), so a stale reply for an
//! already-taken token finds no live slot and drops.
//!
//! # Validate before take
//!
//! Edges that authenticate a reply before committing to it (e.g. a
//! stale-incarnation / session-generation check) use
//! [`ContinuationArena::lookup_token`] to resolve the handle,
//! [`ContinuationArena::get`] to inspect the parked payload, and only
//! then [`ContinuationArena::take`]. A failed check leaves the parked
//! continuation — and any reply lease it owns — untouched, so the
//! mismatch drops the reply without consuming the still-pending
//! operation. [`ContinuationArena::take_by_token`] folds lookup+take
//! into one call for edges that need no pre-take check.
//!
//! Storage is a [`SegmentedArray`] with an `active` tombstone and slot
//! reuse, mirroring [`crate::event_loop::CookieTable`]: indices are
//! stable, growth is allocator-injected, and a taken slot's payload is
//! dropped at take time (so an owned reply lease or capability inside
//! `C` is released promptly, not deferred to arena drop).

use crate::segmented_array::{SegError, SegmentAllocator, SegmentedArray};

/// Bit the kernel reserves for synchronous `MP_CALL` transaction ids.
/// Async continuation tokens keep it clear so they never collide with
/// a sync-call reply on a shared pipe.
const TOKEN_KERNEL_SYNC_BIT: u64 = 1u64 << 63;

/// Stable, ABA-safe reference to a parked continuation.
///
/// Pins the slot index and the epoch live at resolve time. A handle
/// whose epoch no longer matches its slot (the slot was taken and
/// reused) resolves to `None`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ContHandle {
    slot: u32,
    epoch: u32,
}

impl ContHandle {
    /// Sentinel handle that never resolves to a live slot.
    pub const INVALID: ContHandle = ContHandle {
        slot: u32::MAX,
        epoch: 0,
    };

    #[inline]
    pub const fn is_valid(self) -> bool {
        self.slot != u32::MAX
    }

    #[inline]
    pub const fn slot(self) -> u32 {
        self.slot
    }

    #[inline]
    pub const fn epoch(self) -> u32 {
        self.epoch
    }
}

/// One arena slot. `active == false` marks a tombstoned slot available
/// for reuse; its `payload` has already been taken (`None`).
struct ContSlot<C> {
    token: u64,
    epoch: u32,
    active: bool,
    payload: Option<C>,
}

/// Token-keyed store of suspended continuations. See module docs.
pub struct ContinuationArena<C> {
    slots: SegmentedArray<ContSlot<C>>,
    next_token: u64,
    live: u32,
}

impl<C> ContinuationArena<C> {
    /// Construct an empty arena. No memory is reserved until the first
    /// [`Self::alloc`] / [`Self::alloc_with_token`].
    pub const fn new_empty() -> Self {
        Self {
            slots: SegmentedArray::new_empty(),
            next_token: 1,
            live: 0,
        }
    }

    /// Number of live (parked) continuations.
    #[inline]
    pub fn live(&self) -> u32 {
        self.live
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Hand out the next correlation token: monotonic, never `0`,
    /// never bit 63 set — safe to stamp onto a reply-marked `MP_WRITE`
    /// without colliding with a kernel sync-call reply.
    pub fn alloc_token(&mut self) -> u64 {
        loop {
            let raw = self.next_token;
            self.next_token = self.next_token.wrapping_add(1);
            let token = raw & !TOKEN_KERNEL_SYNC_BIT;
            if token != 0 {
                return token;
            }
        }
    }

    /// Park `payload` under a freshly allocated token. Returns the
    /// stable handle and the token to stamp on the outbound request.
    ///
    /// # Safety
    ///
    /// `alloc` must satisfy the [`SegmentAllocator`] contract.
    pub unsafe fn alloc<A: SegmentAllocator>(
        &mut self,
        alloc: &mut A,
        payload: C,
    ) -> Result<(ContHandle, u64), SegError> {
        let token = self.alloc_token();
        let handle = unsafe { self.install(alloc, token, payload)? };
        Ok((handle, token))
    }

    /// Park `payload` under a caller-supplied `token`. The caller owns
    /// the token's invariants: it must be non-zero and low-range (bit
    /// 63 clear), and unique among live continuations (e.g. an op's own
    /// monotonic transaction id). A `0` token is never resolvable via
    /// [`Self::lookup_token`].
    ///
    /// # Safety
    ///
    /// `alloc` must satisfy the [`SegmentAllocator`] contract.
    pub unsafe fn alloc_with_token<A: SegmentAllocator>(
        &mut self,
        alloc: &mut A,
        token: u64,
        payload: C,
    ) -> Result<ContHandle, SegError> {
        unsafe { self.install(alloc, token, payload) }
    }

    /// Reuse the first tombstoned slot, else push a fresh one.
    unsafe fn install<A: SegmentAllocator>(
        &mut self,
        alloc: &mut A,
        token: u64,
        payload: C,
    ) -> Result<ContHandle, SegError> {
        let len = self.slots.len();
        let mut reuse = None;
        for i in 0..len {
            if let Some(slot) = self.slots.get(i) {
                if !slot.active {
                    reuse = Some(i);
                    break;
                }
            }
        }
        if let Some(i) = reuse {
            // Just iterated this index as inactive — get_mut cannot fail.
            if let Some(slot) = self.slots.get_mut(i) {
                slot.token = token;
                slot.active = true;
                slot.payload = Some(payload);
                let epoch = slot.epoch;
                self.live += 1;
                return Ok(ContHandle { slot: i, epoch });
            }
        }
        let slot = unsafe {
            self.slots.push(
                ContSlot {
                    token,
                    epoch: 1,
                    active: true,
                    payload: Some(payload),
                },
                alloc,
            )?
        };
        self.live += 1;
        Ok(ContHandle { slot, epoch: 1 })
    }

    /// Resolve a token to its live slot handle, or `None` when no
    /// active slot carries it (already taken / never parked / `0`).
    pub fn lookup_token(&self, token: u64) -> Option<ContHandle> {
        if token == 0 {
            return None;
        }
        let len = self.slots.len();
        for i in 0..len {
            if let Some(slot) = self.slots.get(i) {
                if slot.active && slot.token == token {
                    return Some(ContHandle {
                        slot: i,
                        epoch: slot.epoch,
                    });
                }
            }
        }
        None
    }

    /// Borrow the parked payload for `handle`, or `None` on a stale
    /// handle (slot taken and reused).
    pub fn get(&self, handle: ContHandle) -> Option<&C> {
        let slot = self.slots.get(handle.slot)?;
        if slot.active && slot.epoch == handle.epoch {
            slot.payload.as_ref()
        } else {
            None
        }
    }

    /// Mutably borrow the parked payload for `handle`.
    pub fn get_mut(&mut self, handle: ContHandle) -> Option<&mut C> {
        let slot = self.slots.get_mut(handle.slot)?;
        if slot.active && slot.epoch == handle.epoch {
            slot.payload.as_mut()
        } else {
            None
        }
    }

    /// Take and remove the parked payload for `handle`, tombstoning the
    /// slot (epoch bump) for reuse. `None` on a stale handle. The
    /// returned `C` carries any reply lease the continuation owned; the
    /// caller must drive it to a terminal action.
    pub fn take(&mut self, handle: ContHandle) -> Option<C> {
        let slot = self.slots.get_mut(handle.slot)?;
        if !slot.active || slot.epoch != handle.epoch {
            return None;
        }
        let payload = slot.payload.take();
        slot.active = false;
        slot.token = 0;
        slot.epoch = slot.epoch.wrapping_add(1);
        if slot.epoch == 0 {
            slot.epoch = 1;
        }
        if payload.is_some() {
            self.live -= 1;
        }
        payload
    }

    /// Resolve `token`, take its payload, and return both the handle
    /// and payload. Convenience for edges that need no pre-take
    /// validation; edges that must authenticate the reply use
    /// [`Self::lookup_token`] + [`Self::get`] + [`Self::take`] so a
    /// failed check leaves the continuation parked.
    pub fn take_by_token(&mut self, token: u64) -> Option<(ContHandle, C)> {
        let handle = self.lookup_token(token)?;
        let payload = self.take(handle)?;
        Some((handle, payload))
    }

    /// Free the slot for `handle` without extracting its payload — the
    /// continuation is *abandoned* (its operation cancelled), not
    /// resumed. The payload is dropped in place, avoiding a by-value
    /// move of a large `C`; the slot is tombstoned and its epoch bumped
    /// for reuse. Returns `true` if a live slot was freed, `false` on a
    /// stale handle. This is the cancel-side counterpart to [`Self::take`]
    /// (which extracts the payload to run the continuation).
    pub fn release(&mut self, handle: ContHandle) -> bool {
        let slot = match self.slots.get_mut(handle.slot) {
            Some(s) => s,
            None => return false,
        };
        if !slot.active || slot.epoch != handle.epoch {
            return false;
        }
        slot.payload = None;
        slot.active = false;
        slot.token = 0;
        slot.epoch = slot.epoch.wrapping_add(1);
        if slot.epoch == 0 {
            slot.epoch = 1;
        }
        self.live = self.live.saturating_sub(1);
        true
    }

    /// Total slots ever allocated (active + tombstoned) — the physical
    /// capacity backing the arena. Pairs with [`Self::free_count`] for
    /// slot-pressure heuristics.
    #[inline]
    pub fn total_cap(&self) -> u32 {
        self.slots.capacity()
    }

    /// Slots currently available for a fresh park — tombstoned slots plus
    /// never-populated capacity. `total_cap() - live()`.
    #[inline]
    pub fn free_count(&self) -> u32 {
        self.slots.capacity().saturating_sub(self.live)
    }

    /// Visit every live continuation. `f` returning `false` stops the
    /// walk early. Teardown sweeps (cancel every continuation belonging
    /// to a departed client) collect handles here and [`Self::take`]
    /// them in a second pass, since taking during the walk would mutate
    /// the slots being iterated.
    pub fn for_each_active<F>(&self, mut f: F)
    where
        F: FnMut(ContHandle, &C) -> bool,
    {
        let len = self.slots.len();
        for i in 0..len {
            if let Some(slot) = self.slots.get(i) {
                if !slot.active {
                    continue;
                }
                let handle = ContHandle {
                    slot: i,
                    epoch: slot.epoch,
                };
                if let Some(payload) = slot.payload.as_ref() {
                    if !f(handle, payload) {
                        return;
                    }
                }
            }
        }
    }
}
