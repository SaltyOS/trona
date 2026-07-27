// SPDX-License-Identifier: GPL-2.0-only
//
//! `OutboundQueue` — retain-on-`WouldBlock` async send queue.
//!
//! A single-threaded reactor that has converted its blocking
//! `mp_call`s to async must not block on the *send* side either. With
//! the reply-enqueue model a reply (or a one-way teardown notify)
//! whose target ring is momentarily full returns
//! `KERNITE_ERR_WOULD_BLOCK` instead of being dropped — but a reactor
//! that *blocks*-retries reintroduces the very cross-reactor cycle the
//! async conversion removes, and dropping loses the reply.
//!
//! This queue closes that gap: a send that `WouldBlock`s is retained
//! and replayed later, woken by a Watch the owning server arms on the
//! target pipe's `STATE_WRITABLE`. The kernel re-asserts and republishes
//! `STATE_WRITABLE` on every ring drain-pop, so the Watch fires reliably
//! once the peer makes room.
//!
//! # Scope
//!
//! Covers the two send shapes the async conversion relies on:
//! [`OutboundKind::Reply`] (a reply-marked `MP_WRITE` echoing a saved
//! request txid) and [`OutboundKind::OneWay`] (a fire-and-forget
//! non-reply `MP_WRITE`, e.g. a teardown notify). Both may carry a
//! single transfer capability.
//!
//! # Capability ownership and layering
//!
//! `trona_server` sits below `trona_runtime` and cannot use its
//! RAII cap types, so a retained entry holds a **raw** `Cap` slot. The
//! lifecycle splits cleanly by outcome:
//!
//! * **sent** — the kernel `take_ref`s the cap out of the server's
//!   CSpace; nothing to clean.
//! * **queued** — the kernel rolled the carrier back on `WouldBlock`,
//!   so the cap stays at its slot; the queue owns it until a later
//!   drain sends it (consumes it) or a discard path cleans it.
//! * **discarded** (peer closed mid-retry, or teardown) — the entry is
//!   dropped without a send, so its cap is still live; the queue hands
//!   the slot to the caller-supplied `cleanup` closure (which performs
//!   the `trona_runtime`-level `cnode_delete`) rather than leaking it.
//! * **error, not queued** — [`OutboundQueue::send_or_queue`] reports
//!   `{ sent: false, queued: false }`; the cap was never transferred,
//!   so the *caller* (which staged it) cleans it.
//!
//! Storage is a [`SegmentedArray`] with an `active` tombstone and slot
//! reuse, mirroring [`crate::event_loop::CookieTable`].

use crate::reply::{MpReplyTarget, mp_write_reply_to};
use crate::segmented_array::{SegError, SegmentAllocator, SegmentedArray};
use trona_kernel::core_types::{Cap, IpcContext, TronaMsg};

/// Inline payload words a retained entry carries — the MP record word
/// capacity, so a full reply body survives a `WouldBlock` intact.
pub const OUTBOUND_INLINE_WORDS: usize = 32;

/// Which send shape a retained entry replays.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutboundKind {
    /// Reply-marked `MP_WRITE` answering a request, echoing the saved
    /// `txid` on the originating pipe.
    Reply,
    /// Non-reply, fire-and-forget `MP_WRITE` to a peer pipe (teardown
    /// notify). No reply is expected.
    OneWay,
}

/// Outcome of [`OutboundQueue::send_or_queue`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutboundResult {
    /// The send completed immediately.
    pub sent: bool,
    /// The send `WouldBlock`ed and was retained for retry. The owning
    /// server must ensure a `STATE_WRITABLE` Watch is armed on the
    /// target pipe.
    pub queued: bool,
}

impl OutboundResult {
    #[inline]
    const fn sent() -> Self {
        Self {
            sent: true,
            queued: false,
        }
    }
    #[inline]
    const fn queued() -> Self {
        Self {
            sent: false,
            queued: true,
        }
    }
    #[inline]
    const fn failed() -> Self {
        Self {
            sent: false,
            queued: false,
        }
    }
}

/// One retained send. `active == false` is a tombstone slot.
struct OutSlot {
    active: bool,
    /// FIFO order stamp — drains replay a target's entries in `seq`
    /// order so reply ordering on a pipe is preserved under backpressure.
    seq: u64,
    mp_slot: Cap,
    txid: u64,
    kind: OutboundKind,
    label: u64,
    len: u8,
    cap: Cap,
    regs: [u64; OUTBOUND_INLINE_WORDS],
}

/// Retain-on-`WouldBlock` send queue. See module docs.
pub struct OutboundQueue {
    slots: SegmentedArray<OutSlot>,
    next_seq: u64,
    pending: u32,
}

impl OutboundQueue {
    pub const fn new_empty() -> Self {
        Self {
            slots: SegmentedArray::new_empty(),
            next_seq: 1,
            pending: 0,
        }
    }

    /// Number of retained (not-yet-sent) entries.
    #[inline]
    pub fn pending(&self) -> u32 {
        self.pending
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pending == 0
    }

    /// Whether any retained entry targets `mp_slot`. Once true, a fresh
    /// send to that slot must queue behind the backlog rather than
    /// jump ahead, preserving per-pipe FIFO order.
    pub fn has_pending_for(&self, mp_slot: Cap) -> bool {
        let len = self.slots.len();
        for i in 0..len {
            if let Some(s) = self.slots.get(i) {
                if s.active && s.mp_slot == mp_slot {
                    return true;
                }
            }
        }
        false
    }

    /// Try to send now; on `WouldBlock` retain for later retry.
    ///
    /// If entries are already queued for `mp_slot`, the immediate-send
    /// attempt is skipped and this entry queues behind them (FIFO).
    /// `cap` is `0` for a payload-only send, else the CSpace slot of a
    /// single capability to transfer.
    ///
    /// # Safety
    ///
    /// `ctx` must be the calling reactor's IPC context. `alloc` must
    /// satisfy the [`SegmentAllocator`] contract. A staged `cap` must
    /// be live in the caller's CSpace at `cap`.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn send_or_queue<A: SegmentAllocator>(
        &mut self,
        alloc: &mut A,
        ctx: *mut IpcContext,
        mp_slot: Cap,
        txid: u64,
        kind: OutboundKind,
        label: u64,
        regs: &[u64],
        cap: Cap,
    ) -> Result<OutboundResult, SegError> {
        let buf = if ctx.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe { (*ctx).ipc_buffer }
        };
        let len = core::cmp::min(regs.len(), OUTBOUND_INLINE_WORDS);
        let mut entry = OutSlot {
            active: true,
            seq: 0,
            mp_slot,
            txid,
            kind,
            label,
            len: len as u8,
            cap,
            regs: {
                let mut words = [0u64; OUTBOUND_INLINE_WORDS];
                words[..len].copy_from_slice(&regs[..len]);
                words
            },
        };

        if !self.has_pending_for(mp_slot) {
            let r = unsafe { Self::try_send(buf, &entry) };
            if r == 0 {
                return Ok(OutboundResult::sent());
            }
            if r != uapi::KERNITE_ERR_WOULD_BLOCK as i32 {
                return Ok(OutboundResult::failed());
            }
        }

        entry.seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        unsafe { self.install(alloc, entry)? };
        self.pending += 1;
        Ok(OutboundResult::queued())
    }

    /// Replay every retained entry for `mp_slot` in FIFO order, stopping
    /// at the first that `WouldBlock`s (the pipe filled again).
    ///
    /// Returns `true` if entries remain queued for `mp_slot` (the
    /// `STATE_WRITABLE` Watch must stay armed), `false` if the backlog
    /// for that slot drained. A peer-closed / errored entry is discarded
    /// and its still-live cap handed to `cleanup`.
    ///
    /// # Safety
    ///
    /// `ctx` must be the calling reactor's IPC context.
    pub unsafe fn drain_writable<F>(
        &mut self,
        ctx: *mut IpcContext,
        mp_slot: Cap,
        mut cleanup: F,
    ) -> bool
    where
        F: FnMut(Cap),
    {
        let buf = if ctx.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe { (*ctx).ipc_buffer }
        };
        loop {
            let Some(idx) = self.lowest_seq_for(mp_slot) else {
                return false;
            };
            let r = {
                let Some(slot) = self.slots.get(idx) else {
                    return false;
                };
                unsafe { Self::try_send(buf, slot) }
            };
            if r == 0 {
                self.free(idx);
                continue;
            }
            if r == uapi::KERNITE_ERR_WOULD_BLOCK as i32 {
                return true;
            }
            // Peer closed or hard error mid-retry: the cap was not
            // transferred, so hand it to the caller's cap-delete before
            // dropping the entry.
            let cap = self.slots.get(idx).map(|s| s.cap).unwrap_or(0);
            if cap != 0 {
                cleanup(cap);
            }
            self.free(idx);
        }
    }

    /// Discard every retained entry, handing each still-live transfer
    /// cap to `cleanup`. Used on server teardown so no queued cap leaks.
    pub fn cancel_all<F>(&mut self, mut cleanup: F)
    where
        F: FnMut(Cap),
    {
        let len = self.slots.len();
        for i in 0..len {
            if let Some(s) = self.slots.get_mut(i) {
                if s.active {
                    if s.cap != 0 {
                        cleanup(s.cap);
                    }
                    s.active = false;
                }
            }
        }
        self.pending = 0;
    }

    /// Reply / one-way `MP_WRITE` of a single retained entry. Stages the
    /// entry's transfer cap (if any) in `buf.caps[0]` for the write and
    /// clears the slot afterward (the kernel consumes it on success;
    /// clearing avoids a stale staged slot on `WouldBlock`).
    unsafe fn try_send(buf: *mut uapi::kernite_ipc_buffer, slot: &OutSlot) -> i32 {
        let cap_count: u64 = if slot.cap != 0 { 1 } else { 0 };
        if cap_count == 1 && !buf.is_null() {
            unsafe { (*buf).caps[0] = slot.cap };
        }
        let payload = &slot.regs[..slot.len as usize];
        let r = match slot.kind {
            OutboundKind::Reply => {
                let target = MpReplyTarget::new(slot.mp_slot, slot.txid);
                unsafe { mp_write_reply_to(buf, target, slot.label, payload, cap_count) }
            }
            OutboundKind::OneWay => {
                let msg = TronaMsg {
                    label: slot.label,
                    length: slot.len as u64,
                    regs: slot.regs,
                };
                let mut ctx = IpcContext {
                    ipc_buffer: buf,
                    send_cap_count: cap_count as i32,
                };
                unsafe {
                    trona_kernel::ipc::mp_write_ctx(&raw mut ctx, slot.mp_slot, &raw const msg)
                }
            }
        };
        if cap_count == 1 && !buf.is_null() {
            unsafe { (*buf).caps[0] = 0 };
        }
        r
    }

    /// Reuse the first tombstoned slot, else push a fresh one.
    unsafe fn install<A: SegmentAllocator>(
        &mut self,
        alloc: &mut A,
        entry: OutSlot,
    ) -> Result<(), SegError> {
        let len = self.slots.len();
        let mut reuse = None;
        for i in 0..len {
            if let Some(s) = self.slots.get(i) {
                if !s.active {
                    reuse = Some(i);
                    break;
                }
            }
        }
        if let Some(i) = reuse {
            if let Some(s) = self.slots.get_mut(i) {
                *s = entry;
                return Ok(());
            }
        }
        unsafe { self.slots.push(entry, alloc)? };
        Ok(())
    }

    /// Index of the lowest-`seq` active entry targeting `mp_slot`.
    fn lowest_seq_for(&self, mp_slot: Cap) -> Option<u32> {
        let len = self.slots.len();
        let mut best: Option<(u32, u64)> = None;
        for i in 0..len {
            if let Some(s) = self.slots.get(i) {
                if s.active && s.mp_slot == mp_slot {
                    match best {
                        Some((_, bseq)) if bseq <= s.seq => {}
                        _ => best = Some((i, s.seq)),
                    }
                }
            }
        }
        best.map(|(i, _)| i)
    }

    /// Tombstone the slot at `idx`.
    fn free(&mut self, idx: u32) {
        if let Some(s) = self.slots.get_mut(idx) {
            if s.active {
                s.active = false;
                s.cap = 0;
                self.pending = self.pending.saturating_sub(1);
            }
        }
    }
}
