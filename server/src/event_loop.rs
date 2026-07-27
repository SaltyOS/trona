// SPDX-License-Identifier: GPL-2.0-only
//
//! Common `EQ_WAIT → cookie demux → MP_READ → dispatch` reactor.
//!
//! Every server (init / namesrv / rsrcsrv / mmsrv / vfs) shares
//! the same outer loop: block on a master `EventQueue`, drain the
//! `EventRecord` published into the IPC buffer's reserved area,
//! decode the cookie back into `(kind, slot, live_gen)`, route to
//! the right `MessagePipe` recv side, drain the inbound message,
//! and dispatch. The boilerplate (kernel ABI surface, generation
//! validation, overflow / timer fan-out) lives here so each
//! server's owner thread only spells out the substantive routing.
//!
//! # Cookie layout
//!
//! ```text
//! bit 63..56  kind        (u8)   server-defined event-source class
//! bit 55..32  slot        (u24)  index into the dispatcher's table
//! bit 31..0   live_gen    (u32)  monotonic per-arm; mismatched
//!                                values fail `lookup` so stale
//!                                fires drop after teardown
//! ```
//!
//! [`encode_cookie`] / [`decode_cookie`] are `const fn` so callers
//! can build cookie literals at compile time when the slot or kind
//! is known statically.
//!
//! # Dispatch contract
//!
//! [`EqDispatcher`] separates two duties:
//!
//! - **`resolve_mp_recv(cookie) -> Option<Cap>`** is read-only and
//!   runs *before* the inbound `MP_READ`. It looks the cookie up in
//!   the dispatcher's [`CookieTable`], validates the generation,
//!   and returns the source MP recv cap. Returning `None` drops
//!   the event silently — the typical case is a stale cookie left
//!   over from a torn-down session.
//! - **`dispatch_state(cookie, msg, badge) -> i32`** is mutable and
//!   runs *after* the message has been read. It consumes the
//!   message and updates dispatcher state.
//!
//! Splitting the two avoids a Rust borrow conflict — the cookie
//! table read is independent of the table write that the dispatch
//! body may issue, and NLL drops the immutable borrow as soon as
//! the resolved cap is copied out.
//!
//! # CookieTable as the dispatcher's table
//!
//! [`CookieTable<T>`] is a thin layer over [`SegmentedArray`]
//! ([`crate::segmented_array`]) that stamps every slot with a
//! `live_gen` and an `active` flag. `cancel(kind, slot)` tombstones
//! the slot — `active = false` plus a `live_gen` bump — and the
//! reactor's next `lookup` for the old cookie returns `None`. The
//! slot index itself is reusable on the next `arm`; the
//! `SegmentedArray` invariant that indices are stable is preserved
//! because the underlying storage is never shifted.
//!
//! # Owned (`Drop`) payloads in `CookieEntry`
//!
//! `CookieEntry`'s `mp_recv` / `watch_cap` are **raw borrowed**
//! capabilities: [`CookieTable::cancel`] zeroes the fields without
//! `cnode_delete`, and the caller owns their lifecycle. `cancel`
//! likewise does **not** run `target`'s `Drop` — a tombstoned
//! `target` is dropped only when the slot is reused by a later
//! [`CookieTable::arm`] (the `entry.target = target` assignment drops
//! the stale value) or when the table is dropped. So keep owned
//! capabilities **out** of `target`: store them in a
//! [`TrackedSlab`](crate::slab::TrackedSlab) whose `slot_free` you
//! drive, and reference them from `target` by id. Embedding an
//! `OwnedCap` directly in `target` is sound but releases it only on
//! reuse / table `Drop`, never on `cancel`.

use crate::segmented_array::{SegError, SegmentAllocator, SegmentedArray};
use trona_kernel::core_types::{Cap, IpcContext, TronaMsg};
use trona_kernel::ipc;
use trona_kernel::ipc_buffer;

/// Encode `(kind, slot, live_gen)` into the 64-bit cookie the
/// kernel publishes back through `EventRecord.cookie`.
#[inline]
pub const fn encode_cookie(kind: u8, slot: u32, live_gen: u32) -> u64 {
    ((kind as u64) << 56) | (((slot as u64) & 0x00FF_FFFF) << 32) | (live_gen as u64)
}

/// Recover `(kind, slot, live_gen)` from a published cookie.
#[inline]
pub const fn decode_cookie(cookie: u64) -> (u8, u32, u32) {
    let kind = ((cookie >> 56) & 0xff) as u8;
    let slot = ((cookie >> 32) & 0x00FF_FFFF) as u32;
    let live_gen = (cookie & 0xFFFF_FFFF) as u32;
    (kind, slot, live_gen)
}

/// One slot in a [`CookieTable`].
///
/// `active = false` + `live_gen` bump is the tombstone state; the
/// slot index becomes free for the next `arm`, but any stale fire
/// still in transit fails the generation check on `lookup` and is
/// dropped.
#[repr(C)]
pub struct CookieEntry<T> {
    pub mp_recv: Cap,
    pub watch_cap: Cap,
    pub live_gen: u32,
    pub kind: u8,
    pub active: bool,
    pub target: T,
}

/// Stable-index registry of armed Watches keyed by cookie.
///
/// Storage is [`SegmentedArray<CookieEntry<T>>`] so slot indices
/// never shift. `cancel` tombstones an entry; `arm` reuses the
/// first inactive slot before appending fresh storage.
pub struct CookieTable<T> {
    entries: SegmentedArray<CookieEntry<T>>,
    next_live_gen: u32,
}

impl<T> CookieTable<T> {
    pub const fn new_empty() -> Self {
        Self {
            entries: SegmentedArray::new_empty(),
            next_live_gen: 1,
        }
    }

    /// Number of slots ever allocated (active + tombstoned).
    #[inline]
    pub fn len(&self) -> u32 {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Allocate the next live generation. Wraps to 1 on overflow so
    /// the value 0 stays reserved as "uninitialised".
    fn alloc_live_gen(&mut self) -> u32 {
        let live_gen = self.next_live_gen;
        let next = self.next_live_gen.wrapping_add(1);
        self.next_live_gen = if next == 0 { 1 } else { next };
        live_gen
    }

    /// Register a fresh `(kind, mp_recv, watch_cap, target)` and
    /// return the cookie the caller should hand to
    /// `WATCH_REGISTER`. Reuses the first inactive slot if one
    /// exists; otherwise appends a new slot via `alloc`.
    ///
    /// # Safety
    ///
    /// `alloc` must satisfy the [`SegmentAllocator`] contract.
    pub unsafe fn arm<A: SegmentAllocator>(
        &mut self,
        alloc: &mut A,
        kind: u8,
        mp_recv: Cap,
        watch_cap: Cap,
        target: T,
    ) -> Result<u64, SegError> {
        let live_gen = self.alloc_live_gen();

        let len = self.entries.len();
        for i in 0..len {
            if let Some(entry) = self.entries.get_mut(i) {
                if !entry.active {
                    entry.mp_recv = mp_recv;
                    entry.watch_cap = watch_cap;
                    entry.live_gen = live_gen;
                    entry.kind = kind;
                    entry.active = true;
                    entry.target = target;
                    return Ok(encode_cookie(kind, i, live_gen));
                }
            }
        }

        let new_entry = CookieEntry {
            mp_recv,
            watch_cap,
            live_gen,
            kind,
            active: true,
            target,
        };
        let slot = unsafe { self.entries.push(new_entry, alloc)? };
        Ok(encode_cookie(kind, slot, live_gen))
    }

    /// Tombstone the slot at `(kind, slot)`. Returns the
    /// previously-registered Watch cap so the caller can issue
    /// `WATCH_CANCEL` on it. Returns `None` when the slot is
    /// already inactive or its `kind` mismatches.
    pub fn cancel(&mut self, kind: u8, slot: u32) -> Option<Cap> {
        let entry = self.entries.get_mut(slot)?;
        if !entry.active || entry.kind != kind {
            return None;
        }
        let watch_cap = entry.watch_cap;
        entry.active = false;
        entry.watch_cap = 0;
        entry.mp_recv = 0;
        // `live_gen` stays put — the lookup-time mismatch already
        // happens via the `active` check, and bumping here would
        // double-spend a generation that was never consumed.
        Some(watch_cap)
    }

    /// Resolve a cookie published by the kernel back to its live
    /// entry. Returns `None` when the slot is tombstoned, the
    /// `kind` mismatches, or the `live_gen` is stale.
    pub fn lookup(&self, cookie: u64) -> Option<&CookieEntry<T>> {
        let (kind, slot, live_gen) = decode_cookie(cookie);
        let entry = self.entries.get(slot)?;
        if !entry.active || entry.kind != kind || entry.live_gen != live_gen {
            return None;
        }
        Some(entry)
    }

    /// Mutable variant of [`Self::lookup`].
    pub fn lookup_mut(&mut self, cookie: u64) -> Option<&mut CookieEntry<T>> {
        let (kind, slot, live_gen) = decode_cookie(cookie);
        let entry = self.entries.get_mut(slot)?;
        if !entry.active || entry.kind != kind || entry.live_gen != live_gen {
            return None;
        }
        Some(entry)
    }
}

/// Reply-routing metadata for the MessagePipe record the reactor just
/// drained, passed to [`EqDispatcher::dispatch_state`].
///
/// `flags` carries the kernel `mp_flags` — notably
/// `KERNITE_MP_FLAG_REPLY`, set when the record is a reply-marked
/// `MP_WRITE` answering an async request this server previously issued
/// — and `txid` the kernel `mp_txid` the reply echoes. A dispatcher
/// that issues async cross-server calls routes
/// `flags & KERNITE_MP_FLAG_REPLY != 0` records to its continuation
/// arena by `txid` before falling through to request dispatch. Servers
/// that issue no async calls ignore `flags` / `txid` and read only
/// `badge`.
#[derive(Clone, Copy, Debug)]
pub struct MpReadMeta {
    /// Sending peer's badge (the value formerly passed as the bare
    /// `badge` argument).
    pub badge: u64,
    /// Kernel `mp_flags` of the drained record.
    pub flags: u64,
    /// Kernel `mp_txid` of the drained record.
    pub txid: u64,
}

impl MpReadMeta {
    /// Metadata for a read-less state dispatch (e.g. `STATE_PEER_CLOSED`,
    /// where the reactor resolves no recv pipe and drains no record, so
    /// there is no badge / reply metadata to carry).
    pub const NONE: MpReadMeta = MpReadMeta {
        badge: 0,
        flags: 0,
        txid: 0,
    };
}

/// Trait servers implement to plug into [`EventLoop`].
///
/// Implementers typically own a [`CookieTable<TheirTarget>`] and
/// use it to satisfy `resolve_mp_recv`. `dispatch_state` then
/// branches on `(kind, slot)` (decoded from the cookie) to route
/// the message into the substantive handler.
pub trait EqDispatcher {
    /// Look up the source MessagePipe recv cap for a cookie. The
    /// reactor calls this *before* draining the message so the
    /// inbound `MP_READ` can target the right pipe.
    ///
    /// Returning `None` causes the reactor to drop the event
    /// without an `MP_READ` — the standard handling for a stale
    /// cookie left over from a teardown that has not yet purged
    /// every queued record.
    fn resolve_mp_recv(&self, cookie: u64) -> Option<Cap>;

    /// Consume the message that was just drained from the pipe
    /// resolved by [`Self::resolve_mp_recv`]. `meta` carries the
    /// drained record's badge plus the kernel reply-routing metadata
    /// ([`MpReadMeta`]); a dispatcher that issues async cross-server
    /// calls inspects `meta.flags` / `meta.txid` to peel replies off to
    /// its continuation arena before request dispatch.
    fn dispatch_state(&mut self, cookie: u64, msg: &TronaMsg, meta: MpReadMeta) -> i32;

    /// Prepare the receive destination for the next `MP_READ`.
    ///
    /// The reactor can drain multiple records from the same readable
    /// source before re-arming its one-shot Watch, so the dispatcher
    /// must clear/re-arm any receive scratch before every read.
    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        true
    }

    /// Re-arm the readable source after the reactor has drained it to
    /// `KERNITE_ERR_WOULD_BLOCK`.
    fn rearm_state_source(&mut self, _cookie: u64) -> i32 {
        0
    }

    /// Decide whether the reactor may keep draining this readable
    /// source after a successful dispatch.
    ///
    /// Most servers can process a batch under one wake. Dispatchers
    /// that park work for an outer loop to run after `run_iteration`
    /// returns should return `false` so the reactor re-arms and yields
    /// after one message.
    fn continue_readable_drain(&mut self, _cookie: u64) -> bool {
        true
    }

    /// Handle a terminal `MP_READ` failure after a state Watch fired.
    ///
    /// The reactor owns watch re-arming. A terminal read error is
    /// still a consumed one-shot watch event; if the source remains
    /// live, dropping the event without re-arming permanently loses
    /// the next readable edge for that source.
    fn handle_mp_read_error(
        &mut self,
        _cookie: u64,
        err: i32,
        _state_set: u64,
        _status: u32,
    ) -> i32 {
        err
    }

    /// Handle an `EVENT_TYPE_OVERFLOW` record. `dropped` is the
    /// kernel's count of state events lost since the last drain.
    fn handle_overflow(&mut self, dropped: u64);

    /// Handle an `EVENT_TYPE_TIMER` record. `cookie` is the value
    /// the caller passed to `TIMER_SET`.
    fn handle_timer(&mut self, cookie: u64);

    /// `EVENT_TYPE_PIPE` (rare) — kernel published an inbound MP
    /// record directly to the queue instead of going through a
    /// Watch on `STATE_READABLE`. The reactor cannot resolve the
    /// source MP recv on its own (the dispatcher's cookie table
    /// is what makes that mapping authoritative), so the
    /// dispatcher does its own `MP_READ`. Default: drop. The
    /// canonical path is the STATE-Watch route; this is an escape
    /// hatch for any caller the kernel still publishes PIPE
    /// records for.
    fn dispatch_pipe(&mut self, _ctx: *mut IpcContext, _cookie: u64) -> i32 {
        0
    }

    /// Catch-all for event kinds the reactor's standard match
    /// arms do not cover (IRQ, USER, etc.). Default: drop.
    fn handle_other(&mut self, _kind: u32, _record_cookie: u64) -> i32 {
        0
    }

    /// Handle an `EVENT_TYPE_PAGER_REQUEST` record. The kernel
    /// publishes these on an `OBJ_PAGER`-bound EventQueue whenever
    /// a file-backed MO faults on an absent page. The pager-owning
    /// task (typically vfs) resolves the kernel-supplied `mo_id`
    /// (carried in `record.object_id`), fetches the page from its
    /// backend, and replies via `PAGER_SUPPLY_PAGE` / `PAGER_FAIL`.
    ///
    /// The full `EventRecord` is forwarded so the dispatcher can
    /// read `cookie`, `object_id` (mo_id), `state_set`
    /// (access_flags), `payload0` (page_idx), `payload1` (length),
    /// and `payload2` (faulting tcb trace_id) without re-parsing
    /// the IPC buffer.
    ///
    /// Default: drop. Servers that do not own a pager (init /
    /// namesrv / rsrcsrv / mmsrv) inherit the default and never
    /// receive these events anyway, since the kernel only routes
    /// `EVENT_TYPE_PAGER_REQUEST` to EQs that have an attached
    /// pager bound via `PAGER_BIND_EQ`.
    fn handle_pager_request(&mut self, _record: &uapi::kernite_event_record) -> i32 {
        0
    }
}

/// Reactor that drives the shared `EQ_WAIT → cookie → MP_READ →
/// dispatch` loop. Owns the master `EventQueue` cap and a
/// dispatcher; the dispatcher owns its own [`CookieTable`].
pub struct EventLoop<D: EqDispatcher> {
    pub eq_cap: Cap,
    pub dispatch: D,
}

impl<D: EqDispatcher> EventLoop<D> {
    pub const fn new(eq_cap: Cap, dispatch: D) -> Self {
        Self { eq_cap, dispatch }
    }

    /// One full reactor iteration: block on `eq_cap`, drain one
    /// event, route it.
    ///
    /// Returns 0 on a clean state-event dispatch (whatever the
    /// dispatcher returned), 0 for overflow / timer / unknown
    /// kinds (the dispatcher handlers are infallible from the
    /// reactor's side), or a negative `KERNITE_ERR_*` on kernel
    /// surface failure (`EQ_WAIT` failed, IPC buffer is null,
    /// `MP_READ` failed). A returned 0 does not necessarily mean
    /// "made progress" — it can also mean "stale cookie dropped".
    ///
    /// # Safety
    ///
    /// `ctx` must point at the calling thread's IPC context, and
    /// the IPC buffer page that context references must be mapped
    /// into the current address space.
    pub unsafe fn run_iteration(&mut self, ctx: *mut IpcContext) -> i32 {
        unsafe { self.run_iteration_with_wait_hooks(ctx, || {}, || {}) }
    }

    /// Variant of [`Self::run_iteration`] for callers that hold
    /// an outer lock around shared dispatcher state. The reactor
    /// invokes `release_before_wait` immediately before the
    /// long-blocking `EQ_WAIT` and `acquire_after_wait`
    /// immediately after the wait returns (success or failure),
    /// so peer reactors sharing the same lock can make progress
    /// while one is parked on the queue. The dispatcher half —
    /// `resolve_mp_recv` / `mp_read_ctx` / `dispatch_state` —
    /// always runs with the lock held.
    ///
    /// Returns with the outer lock held on every code path;
    /// callers re-enter in a loop and re-arm any per-iteration
    /// state under the same lock between calls.
    ///
    /// # Safety
    ///
    /// `ctx` must point at the calling thread's IPC context.
    /// `release_before_wait` and `acquire_after_wait` must
    /// release / re-take the same lock; failing to keep the
    /// pair matched leaks lock state into post-wait dispatch.
    /// Caller must hold the lock before the first call.
    pub unsafe fn run_iteration_with_wait_hooks<R, A>(
        &mut self,
        ctx: *mut IpcContext,
        mut release_before_wait: R,
        mut acquire_after_wait: A,
    ) -> i32
    where
        R: FnMut(),
        A: FnMut(),
    {
        release_before_wait();
        let eq_err = trona_kernel::syscall::invoke(
            self.eq_cap,
            uapi::KERNITE_INV_EQ_WAIT as u64,
            // The event loop blocks indefinitely for the next event; a
            // timed wait would pass a finite absolute deadline here.
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            0,
            0,
            0,
        );
        acquire_after_wait();
        if eq_err.error != 0 {
            return eq_err.error as i32;
        }
        unsafe { self.dispatch_ready_event(ctx) }
    }

    /// Drain the `EventRecord` the kernel has just published into
    /// `ctx`'s IPC buffer reserved area and route it through the
    /// dispatcher. The caller must already hold any outer locks
    /// the dispatcher's handlers expect — this helper does not
    /// block, only reads / dispatches.
    unsafe fn dispatch_ready_event(&mut self, ctx: *mut IpcContext) -> i32 {
        let buf = unsafe { (*ctx).ipc_buffer };
        if buf.is_null() {
            return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
        }
        let record = unsafe { ipc_buffer::read_event_record(buf as *const _) };

        let kind = record.kind;
        if kind == uapi::KERNITE_EVENT_TYPE_STATE {
            // resolve_mp_recv returns Some(cap) for read-driven
            // states (e.g. `STATE_READABLE` on a MessagePipe recv —
            // the dispatcher wants the inbound record drained
            // before its handler runs) and None for read-less
            // states (e.g. `STATE_PEER_CLOSED` on a registered cap
            // — there is no message to drain, only a transition
            // to act on). Stale cookies also surface as None; the
            // dispatcher's `dispatch_state` re-checks the cookie
            // table itself and drops them.
            let mp_recv_opt = self.dispatch.resolve_mp_recv(record.cookie);
            if let Some(mp_recv) = mp_recv_opt {
                return unsafe { self.drain_readable_source(ctx, &record, mp_recv) };
            }
            let msg = TronaMsg::zeroed();
            self.dispatch
                .dispatch_state(record.cookie, &msg, MpReadMeta::NONE)
        } else if kind == uapi::KERNITE_EVENT_TYPE_TIMER {
            self.dispatch.handle_timer(record.cookie);
            0
        } else if kind == uapi::KERNITE_EVENT_TYPE_OVERFLOW {
            self.dispatch.handle_overflow(record.payload0);
            0
        } else if kind == uapi::KERNITE_EVENT_TYPE_PIPE {
            self.dispatch.dispatch_pipe(ctx, record.cookie)
        } else if kind == uapi::KERNITE_EVENT_TYPE_PAGER_REQUEST {
            self.dispatch.handle_pager_request(&record)
        } else {
            self.dispatch.handle_other(kind, record.cookie)
        }
    }

    unsafe fn drain_readable_source(
        &mut self,
        ctx: *mut IpcContext,
        record: &uapi::kernite_event_record,
        mp_recv: Cap,
    ) -> i32 {
        loop {
            let mut msg = TronaMsg::zeroed();
            let mut badge: u64 = 0;
            let read_err = unsafe {
                self.read_mp_nonblocking(record.cookie, ctx, mp_recv, &raw mut msg, &raw mut badge)
            };
            if read_err == 0 {
                let meta = unsafe { read_mp_meta(ctx, badge) };
                let dispatch_err = self.dispatch.dispatch_state(record.cookie, &msg, meta);
                if dispatch_err != 0 {
                    let rearm_err = self.dispatch.rearm_state_source(record.cookie);
                    return if rearm_err != 0 {
                        rearm_err
                    } else {
                        dispatch_err
                    };
                }
                // A handler may consume the final message for a source
                // and tombstone its cookie as part of teardown. In that
                // case the original one-shot Watch must not be re-armed,
                // and a second `MP_READ` would report a spurious local
                // prepare failure.
                if self.dispatch.resolve_mp_recv(record.cookie).is_none() {
                    return 0;
                }
                if !self.dispatch.continue_readable_drain(record.cookie) {
                    return self.dispatch.rearm_state_source(record.cookie);
                }
                continue;
            }
            if read_err == uapi::KERNITE_ERR_WOULD_BLOCK as i32 {
                return self.dispatch.rearm_state_source(record.cookie);
            }
            if read_err == uapi::KERNITE_ERR_SLOT_OCCUPIED as i32
                && self.dispatch.prepare_mp_read(record.cookie)
            {
                continue;
            }
            let handler_err = self.dispatch.handle_mp_read_error(
                record.cookie,
                read_err,
                record.state_set,
                record.status,
            );
            let rearm_err = self.dispatch.rearm_state_source(record.cookie);
            return if rearm_err != 0 {
                rearm_err
            } else {
                handler_err
            };
        }
    }

    unsafe fn read_mp_nonblocking(
        &mut self,
        cookie: u64,
        ctx: *mut IpcContext,
        mp_recv: Cap,
        msg: *mut TronaMsg,
        badge: *mut u64,
    ) -> i32 {
        if !self.dispatch.prepare_mp_read(cookie) {
            return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
        }
        if ctx.is_null() {
            return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
        }
        // `MP_READ` is non-blocking by contract; an empty pipe returns
        // `WouldBlock` for the dispatcher's error handler to classify.
        unsafe { ipc::mp_read_ctx(ctx, mp_recv, msg, badge) }
    }
}

/// Read the kernel reply-routing metadata (`mp_flags` / `mp_txid`) that
/// the most recent `MP_READ` left in the IPC buffer, paired with the
/// badge the reactor captured during the read. A null context or buffer
/// yields zeroed reply metadata (the badge is still carried).
#[inline]
unsafe fn read_mp_meta(ctx: *mut IpcContext, badge: u64) -> MpReadMeta {
    if ctx.is_null() {
        return MpReadMeta {
            badge,
            flags: 0,
            txid: 0,
        };
    }
    let buf = unsafe { (*ctx).ipc_buffer };
    if buf.is_null() {
        return MpReadMeta {
            badge,
            flags: 0,
            txid: 0,
        };
    }
    MpReadMeta {
        badge,
        flags: unsafe { (*buf).mp_flags },
        txid: unsafe { (*buf).mp_txid },
    }
}
