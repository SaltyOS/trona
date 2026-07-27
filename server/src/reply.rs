// SPDX-License-Identifier: GPL-2.0-only
//
//! Reply endpoint helpers — common reply-marked `MP_WRITE` sender plus the
//! single-consume lease guard for saved reply endpoints.
//!
//! Regular `MP_CALL` records are answered by writing a reply record
//! on the MessagePipe endpoint that delivered the request. Servers
//! are still obliged to take exactly one terminal action against the
//! saved endpoint lease (send the reply, drop/cancel, park the lease,
//! or explicitly disarm it). Forgetting the action can leave the
//! originating client blocked.
//!
//! `ReplyLease` is a low-level state machine + RAII Drop guard around
//! a reply endpoint slot. Servers can hand it to higher-level reply
//! machinery (PendingOp arena, dependency graph, first-error
//! propagation, cancellable async ops, multi-stage replies, etc.).
//! The lease itself does not write the reply or call `cnode_delete` —
//! the actual wire transitions live in the calling server's typed
//! reply path. The lease only enforces the single-consume invariant
//! and explicit lifecycle outcomes. Servers compose this with their
//! own dispatch state to get end-to-end coverage.
//!
//! Drop policy: `Active` at drop time is a programming error. In
//! debug builds the Drop impl panics so the regression surfaces in
//! tests; in release builds the lease silently drops to keep
//! production safe in the face of complex async / parked / cancelled
//! lifecycles where the panic would be too strong.

use trona_kernel::core_types::{Cap, IpcContext, TronaMsg};

/// Result of publishing a reply with an optional error-only fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyConsumeResult {
    /// Result of the caller-requested consume. `0` means the intended
    /// reply was published.
    pub primary_error: i32,
    /// Result of the error-only fallback consume. `0` means either no
    /// fallback was needed or the fallback was published.
    pub fallback_error: i32,
}

impl ReplyConsumeResult {
    #[inline]
    pub const fn ok() -> Self {
        Self {
            primary_error: 0,
            fallback_error: 0,
        }
    }

    #[inline]
    pub const fn primary_failed(primary_error: i32, fallback_error: i32) -> Self {
        Self {
            primary_error,
            fallback_error,
        }
    }
}

/// Explicit destination for a MessagePipe call reply.
///
/// The endpoint slot and `MP_CALL` transaction id are captured when a
/// request is read. Reply paths should carry this value instead of
/// relying on the current IPC buffer's ambient `mp_txid` later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpReplyTarget {
    pub mp_slot: Cap,
    pub txid: u64,
}

impl MpReplyTarget {
    #[inline]
    pub const fn none() -> Self {
        Self {
            mp_slot: 0,
            txid: 0,
        }
    }

    #[inline]
    pub const fn new(mp_slot: Cap, txid: u64) -> Self {
        Self { mp_slot, txid }
    }

    #[inline]
    pub unsafe fn from_ipc_buffer(buf: *const uapi::kernite_ipc_buffer, mp_slot: Cap) -> Self {
        if buf.is_null() || mp_slot == 0 {
            return Self::none();
        }
        unsafe { Self::new(mp_slot, (*buf).mp_txid) }
    }

    #[inline]
    pub const fn is_none(self) -> bool {
        self.mp_slot == 0
    }

    #[inline]
    pub const fn has_txid(self) -> bool {
        self.txid != 0
    }
}

/// Send a regular MessagePipe RPC reply to an explicit target.
///
/// The caller must stage any reply caps in `buf.caps[..cap_count]`
/// before calling. This sends a reply-marked `MP_WRITE`; it is the
/// default server reply path for request records received with
/// `MP_READ`.
///
/// # Safety
///
/// `buf` must be the current thread's IPC buffer. `target` must have
/// been captured from the inbound request record that this reply answers.
pub unsafe fn mp_write_reply_to(
    buf: *mut uapi::kernite_ipc_buffer,
    target: MpReplyTarget,
    label: u64,
    regs: &[u64],
    cap_count: u64,
) -> i32 {
    if buf.is_null() {
        return uapi::KERNITE_ERR_INVALID_ARGUMENT as i32;
    }
    if target.is_none() {
        return uapi::KERNITE_ERR_INVALID_ARGUMENT as i32;
    }
    let len = core::cmp::min(regs.len(), 32);
    let msg = TronaMsg {
        label,
        length: len as u64,
        regs: {
            let mut words = [0u64; 32];
            words[..len].copy_from_slice(&regs[..len]);
            words
        },
    };
    unsafe {
        let mut ctx = IpcContext {
            ipc_buffer: buf,
            send_cap_count: core::cmp::min(cap_count, uapi::KERNITE_IPC_MAX_CAPS as u64) as i32,
        };
        trona_kernel::ipc::mp_write_reply_to_ctx(
            &raw mut ctx,
            target.mp_slot,
            target.txid,
            &raw const msg,
        )
    }
}

/// Send a MessagePipe reply, and if a cap-bearing reply fails before
/// it can publish, retry the same endpoint with an error-only reply.
///
/// This preserves capful-reply fallback behavior without requiring
/// explicit fault-reply ownership for ordinary RPC.
///
/// # Safety
///
/// Same requirements as [`mp_write_reply_to`]. On non-zero `primary_error`,
/// the caller must still dispose of any caps it staged in `buf.caps`.
pub unsafe fn mp_write_reply_to_with_error_fallback(
    buf: *mut uapi::kernite_ipc_buffer,
    target: MpReplyTarget,
    label: u64,
    regs: &[u64],
    cap_count: u64,
) -> ReplyConsumeResult {
    let primary = unsafe { mp_write_reply_to(buf, target, label, regs, cap_count) };
    if primary == 0 {
        return ReplyConsumeResult::ok();
    }
    if cap_count == 0 || buf.is_null() {
        return ReplyConsumeResult::primary_failed(primary, 0);
    }
    unsafe {
        let limit = core::cmp::min(cap_count, uapi::KERNITE_IPC_MAX_CAPS as u64);
        for i in 0..limit {
            (*buf).caps[i as usize] = 0;
        }
    }
    let fallback = unsafe { mp_write_reply_to(buf, target, primary as u64, &[], 0) };
    ReplyConsumeResult::primary_failed(primary, fallback)
}

/// Reply endpoint lease lifecycle. The lease starts `Active` and
/// transitions exactly once into one of the terminal states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyLeaseState {
    /// Saved by the server-loop, awaiting a terminal action.
    Active,
    /// Server consumed the lease — typically wired to a successful
    /// reply write against the reply endpoint.
    Consumed,
    /// Server cancelled the lease without sending a reply — typically
    /// the calling client disconnected or the operation was aborted
    /// server-side.
    Cancelled,
    /// Lease ownership migrated into a deferred / parked structure
    /// (PendingOp arena, deferred FIFO, dependency graph). The active
    /// `ReplyLease` value transitioned through this state on the
    /// way to a `ParkedReply` companion.
    Parked,
    /// Server explicitly disarmed the single-consume guard — the
    /// lease is treated as forfeit without claiming a terminal
    /// outcome. Use this when manual lifecycle bookkeeping replaces
    /// the lease guard.
    Disarmed,
}

/// Saved reply endpoint slot reference, paired with a state machine
/// that enforces single-consume.
///
/// The lease owns the endpoint reference in the sense that exactly one
/// terminal call (`consume` / `cancel` / `park` / `disarm`) is
/// required before drop. The service owns the endpoint cap storage;
/// the lease only carries the `(slot, epoch)` reference and tracks
/// the state transition.
#[must_use = "ReplyLease must be explicitly consumed, cancelled, parked, or disarmed before drop"]
pub struct ReplyLease {
    slot: Cap,
    epoch: u64,
    txid: u64,
    state: ReplyLeaseState,
}

impl ReplyLease {
    /// Take ownership of an inbound reply endpoint reference. `slot`
    /// is the MessagePipe endpoint to answer; `epoch` is
    /// a server-chosen identifier (typically the badge of the
    /// originating client or a monotonic generation counter) so a
    /// stale lease that escapes its original PendingOp can be
    /// detected.
    #[inline]
    pub const fn saved(slot: Cap, epoch: u64) -> Self {
        Self {
            slot,
            epoch,
            txid: 0,
            state: ReplyLeaseState::Active,
        }
    }

    /// Take ownership of an inbound reply endpoint and preserve the
    /// MP_CALL transaction id that must be echoed by the reply write.
    #[inline]
    pub const fn saved_with_txid(slot: Cap, epoch: u64, txid: u64) -> Self {
        Self {
            slot,
            epoch,
            txid,
            state: ReplyLeaseState::Active,
        }
    }

    /// Take ownership of an inbound reply target.
    #[inline]
    pub const fn saved_target(target: MpReplyTarget, epoch: u64) -> Self {
        Self::saved_with_txid(target.mp_slot, epoch, target.txid)
    }

    /// Endpoint slot the lease references. Useful when the calling
    /// server needs to write the reply explicitly before
    /// taking the terminal `consume` action.
    #[inline]
    pub const fn slot(&self) -> Cap {
        self.slot
    }

    /// Server-chosen identifier paired with the slot at `saved`
    /// time. Recovered through PendingOp / parked-token chains so
    /// stale-lease detection has a value to compare against.
    #[inline]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Kernel MP_CALL transaction id to echo on the eventual reply.
    #[inline]
    pub const fn txid(&self) -> u64 {
        self.txid
    }

    #[inline]
    pub const fn target(&self) -> MpReplyTarget {
        MpReplyTarget::new(self.slot, self.txid)
    }

    /// Current state. `Active` at drop time triggers the debug-build
    /// panic.
    #[inline]
    pub const fn state(&self) -> ReplyLeaseState {
        self.state
    }

    /// Mark the lease consumed — the server has wired (or is about
    /// to wire) a reply against the endpoint. The state guard
    /// flips to `Consumed`; subsequent drop is silent in any build.
    ///
    /// Returns the saved `(slot, epoch)` so the caller can plug the
    /// slot into its own storage (typically clearing or reusing the
    /// receive slot pool index).
    #[inline]
    pub fn consume(mut self) -> (Cap, u64) {
        self.state = ReplyLeaseState::Consumed;
        let slot = self.slot;
        let epoch = self.epoch;
        // The `Drop` impl below sees `Consumed` and skips the panic.
        core::mem::forget(self);
        (slot, epoch)
    }

    /// Consume and return the saved txid alongside `(slot, epoch)`.
    #[inline]
    pub fn consume_with_txid(mut self) -> (Cap, u64, u64) {
        self.state = ReplyLeaseState::Consumed;
        let slot = self.slot;
        let epoch = self.epoch;
        let txid = self.txid;
        core::mem::forget(self);
        (slot, epoch, txid)
    }

    /// Consume and return the saved reply target alongside the epoch.
    #[inline]
    pub fn consume_target(mut self) -> (MpReplyTarget, u64) {
        self.state = ReplyLeaseState::Consumed;
        let target = MpReplyTarget::new(self.slot, self.txid);
        let epoch = self.epoch;
        core::mem::forget(self);
        (target, epoch)
    }

    /// Mark the lease cancelled — no reply will be sent, the cap
    /// endpoint reference is no longer expected to emit a reply.
    /// State flips to `Cancelled`.
    #[inline]
    pub fn cancel(mut self) -> (Cap, u64) {
        self.state = ReplyLeaseState::Cancelled;
        let slot = self.slot;
        let epoch = self.epoch;
        core::mem::forget(self);
        (slot, epoch)
    }

    /// Migrate lease ownership into a parked record. The returned
    /// [`ParkedReply`] carries the same `(slot, epoch)`; the
    /// active lease's state guard is forfeit (transition `Parked`).
    /// The parked record can resume the lease later via
    /// [`ParkedReply::unpark`].
    #[inline]
    pub fn park(mut self) -> ParkedReply {
        self.state = ReplyLeaseState::Parked;
        let parked = ParkedReply {
            slot: self.slot,
            epoch: self.epoch,
            txid: self.txid,
        };
        core::mem::forget(self);
        parked
    }

    /// Manually disarm the single-consume guard without claiming a
    /// terminal outcome. Use when an out-of-band lifecycle — typed
    /// reply machinery, bulk teardown, kernel-side cap revocation —
    /// will dispose of the slot. State transitions to `Disarmed`.
    #[inline]
    pub fn disarm(mut self) {
        self.state = ReplyLeaseState::Disarmed;
        core::mem::forget(self);
    }
}

impl Drop for ReplyLease {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        if matches!(self.state, ReplyLeaseState::Active) {
            panic!(
                "reply endpoint lease dropped while Active (slot={:#x}, epoch={:#x}) — \
                 caller forgot to consume / cancel / park / disarm",
                self.slot, self.epoch,
            );
        }
    }
}

/// A reply endpoint lease whose active guard has been parked. Carries
/// the same `(slot, epoch)` and re-emits a fresh `ReplyLease`
/// when the parked record is resumed. Server-side PendingOp arenas
/// and deferred FIFOs typically store this value alongside the
/// suspended request.
#[derive(Clone, Copy, Debug)]
pub struct ParkedReply {
    slot: Cap,
    epoch: u64,
    txid: u64,
}

impl ParkedReply {
    /// Inspect the saved endpoint slot without consuming the parked
    /// record.
    #[inline]
    pub const fn slot(&self) -> Cap {
        self.slot
    }

    /// Inspect the saved epoch without consuming the parked record.
    #[inline]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Inspect the saved MP_CALL txid without consuming the parked record.
    #[inline]
    pub const fn txid(&self) -> u64 {
        self.txid
    }

    #[inline]
    pub const fn target(&self) -> MpReplyTarget {
        MpReplyTarget::new(self.slot, self.txid)
    }

    /// Resume the parked record into a fresh active lease. The new
    /// `ReplyLease` re-imposes the single-consume guard; the
    /// caller must take a terminal action before drop.
    #[inline]
    pub const fn unpark(self) -> ReplyLease {
        ReplyLease {
            slot: self.slot,
            epoch: self.epoch,
            txid: self.txid,
            state: ReplyLeaseState::Active,
        }
    }
}
