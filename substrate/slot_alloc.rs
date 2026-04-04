//! Per-process dynamic capability slot allocator
//!
//! Provides a bump allocator over a chained array of CNode slot segments.
//! The initial segment is assigned by procmgr/init at spawn time. When all
//! segments are exhausted, an expansion protocol requests more slots from
//! the process manager (CSpace expansion via Signal+probe or blocking Call).
//!
//! The pool base and count are communicated via auxv entries
//! `AT_TRONA_SLOT_BASE` and `AT_TRONA_SLOT_COUNT`.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::invoke;
use crate::ipc;
use crate::protocol::PM_EXPAND_CSPACE;
use crate::syscall::syscall;
use crate::types::Cap;

// Standard child CSpace layout
const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_PROCMGR_EP: u64 = 3;

const SLOT_EXPAND_BITS_DEFAULT: u64 = 10;
const MAX_SEGMENTS: usize = 16;

/// A contiguous range of CNode slots available for allocation.
#[derive(Clone, Copy)]
struct Segment {
    base: Cap,
    count: u64,
    next: u64,
}

/// Result of an async slot allocation attempt.
#[derive(Clone, Copy, PartialEq)]
pub enum SlotResult {
    /// Successfully allocated a slot.
    Ok(Cap),
    /// Expansion in progress; caller should yield and retry.
    WouldBlock,
    /// All segments exhausted and expansion failed permanently.
    Exhausted,
}

/// State machine for the CSpace expansion protocol.
#[derive(Clone, Copy, PartialEq)]
enum ExpandState {
    /// No expansion in progress.
    Idle,
    /// Signal sent to procmgr; probing for sub-CNode at deterministic slot.
    Requested,
    /// Expansion permanently failed (segment table full or max expansions).
    Failed,
}

/// Internal state for the per-process slot allocator.
struct SlotAllocState {
    segments: [Segment; MAX_SEGMENTS],
    seg_count: usize,
    active_seg: usize,
    initialized: bool,
    /// Procmgr EP for CSpace expansion (always CAP_PROCMGR_EP).
    procmgr_ep: Cap,
    /// Notification cap for CSpace expansion signaling.
    cspace_ntfn: Cap,
    expand_state: ExpandState,
    /// Root CNode size_bits (queried from cnode_get_info).
    root_bits: u8,
    /// Total CNode depth after expansion (root_bits + sub_bits), 0 if not expanded.
    expanded_depth: u8,
    /// Number of completed CSpace expansions (probed sub-CNodes).
    cspace_expand_count: usize,
}

static mut SLOT_ALLOC: SlotAllocState = SlotAllocState {
    segments: [Segment { base: 0, count: 0, next: 0 }; MAX_SEGMENTS],
    seg_count: 0,
    active_seg: 0,
    initialized: false,
    procmgr_ep: 0,
    cspace_ntfn: 0,
    expand_state: ExpandState::Idle,
    root_bits: 0,
    expanded_depth: 0,
    cspace_expand_count: 0,
};

/// Spinlock protecting SLOT_ALLOC state for thread safety.
static SLOT_LOCK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[inline]
fn slot_lock_acquire() {
    use core::sync::atomic::Ordering;
    while SLOT_LOCK.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        while SLOT_LOCK.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
}

#[inline]
fn slot_lock_release() {
    SLOT_LOCK.store(0, core::sync::atomic::Ordering::Release);
}

/// Guards against concurrent CSpace expansion requests.
/// Only one thread performs the blocking RPC at a time; others yield and retry.
static EXPANDING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Get the procmgr endpoint for CSpace expansion.
///
/// # Safety
/// Must be called after slot_alloc_init.
unsafe fn get_expand_ep() -> Cap {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        if state.procmgr_ep != 0 { state.procmgr_ep } else { CAP_PROCMGR_EP }
    }
}

/// Register a newly expanded CNode segment under SLOT_LOCK.
/// Returns true on success, false if segment table is full.
///
/// # Safety
/// Must be called with SLOT_LOCK held.
unsafe fn register_new_segment(base: Cap, count: u64, _label: &[u8]) -> bool {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if state.seg_count >= MAX_SEGMENTS {
            state.expand_state = ExpandState::Failed;
            return false;
        }

        let si = state.seg_count;
        state.segments[si] = Segment { base, count, next: 0 };
        state.seg_count += 1;
        state.active_seg = si;
        state.expand_state = ExpandState::Idle;
        update_expansion_depth(state);

        crate::udebug!(|_lb| {
            _lb.str(b"[SLOT] expand(");
            _lb.str(_label);
            _lb.str(b"): base=");
            _lb.hex(base);
            _lb.str(b" count=");
            _lb.hex(count);
            _lb.str(b" (seg ");
            _lb.hex(si as u64);
            _lb.str(b")\n");
        });
        true
    }
}

/// Perform CSpace expansion without holding SLOT_LOCK.
///
/// Uses an `EXPANDING` CAS guard so only one thread performs the blocking
/// RPC at a time. Returns true if expansion succeeded or is in progress
/// (caller should retry), false if expansion permanently failed.
fn try_expand(ep: Cap) -> bool {
    use core::sync::atomic::Ordering;
    // Only one thread expands at a time
    if EXPANDING.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        // Another thread is expanding — yield and let caller retry
        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        return true;
    }
    let result = request_expand_blocking(ep);
    EXPANDING.store(false, Ordering::Release);
    match result {
        Some((base, count)) => {
            slot_lock_acquire();
            // SAFETY: SLOT_LOCK held, register_new_segment accesses SLOT_ALLOC safely
            let ok = unsafe { register_new_segment(base, count, b"sync") };
            slot_lock_release();
            ok
        }
        None => false,
    }
}

/// Initialize the per-process slot allocator.
///
/// Called during process startup (from CRT or RTLD) with values from auxv.
/// `base==0` means "not provided".
/// `cspace_ntfn` is the notification cap for CSpace expansion signaling
/// (from AT_TRONA_CSPACE_NTFN auxv), or 0 if not available.
///
/// # Safety
/// Must be called exactly once during process initialization.
pub unsafe fn slot_alloc_init(base: Cap, count: u64, cspace_ntfn: u64) {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        state.segments[0] = Segment { base, count, next: 0 };
        state.seg_count = 1;
        state.active_seg = 0;
        state.initialized = base != 0;
        state.procmgr_ep = CAP_PROCMGR_EP;
        state.cspace_ntfn = cspace_ntfn;
        state.expand_state = ExpandState::Idle;
        state.root_bits = 0;
        state.expanded_depth = 0;
        state.cspace_expand_count = 0;
    }
}

/// Check whether the slot allocator has been initialized.
pub fn slot_alloc_is_initialized() -> bool {
    unsafe { (*(&raw const SLOT_ALLOC)).initialized }
}

/// Return the pool base slot (first segment).
pub fn slot_alloc_base() -> Cap {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        if state.seg_count > 0 { state.segments[0].base } else { 0 }
    }
}

/// Return the total pool size across all segments.
pub fn slot_alloc_count() -> u64 {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        let mut total: u64 = 0;
        for i in 0..state.seg_count {
            total += state.segments[i].count;
        }
        total
    }
}

/// Return the number of slots remaining across all segments.
pub fn slot_alloc_remaining() -> u64 {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        if !state.initialized {
            return 0;
        }
        let mut remaining: u64 = 0;
        for i in state.active_seg..state.seg_count {
            remaining += state.segments[i].count.saturating_sub(state.segments[i].next);
        }
        remaining
    }
}

/// Override the procmgr EP used for expansion (escape hatch).
pub fn slot_alloc_set_procmgr_ep(ep: Cap) {
    unsafe {
        (*(&raw mut SLOT_ALLOC)).procmgr_ep = ep;
    }
}

/// Return the observed CSpace depth after expansion (root_bits + sub_bits).
///
/// Returns 0 if no expansion has occurred (flat single-level CSpace).
/// Used by the thread pool to configure child threads with the correct
/// CSpace depth via `tcb_set_space_with_depth`.
pub fn observed_cspace_depth() -> u8 {
    unsafe { (*(&raw const SLOT_ALLOC)).expanded_depth }
}

/// Async slot allocation with self-healing NBSend expansion protocol.
///
/// Returns `SlotResult::Ok(cap)` on success, `WouldBlock` if expansion is
/// in progress (caller should yield and retry), or `Exhausted` if expansion
/// failed permanently.
pub fn slot_alloc_async() -> SlotResult {
    slot_lock_acquire();
    let result = unsafe { slot_alloc_async_inner() };
    slot_lock_release();
    result
}

unsafe fn slot_alloc_async_inner() -> SlotResult {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized {
            return SlotResult::Exhausted;
        }

        // Fast path: scan segment chain for an available slot
        while state.active_seg < state.seg_count {
            let seg = &mut state.segments[state.active_seg];
            if seg.next < seg.count {
                let slot = seg.base + seg.next;
                seg.next += 1;
                return SlotResult::Ok(slot);
            }
            state.active_seg += 1;
        }

        // All segments exhausted — enter CSpace expansion protocol.
        // Uses Signal+probe: signal the procmgr's bound notification, then
        // probe the deterministic root CNode slot to detect when the sub-CNode
        // has been placed there by the procmgr.
        let ntfn = state.cspace_ntfn;

        match state.expand_state {
            ExpandState::Idle => {
                if ntfn == 0 || state.cspace_expand_count >= MAX_CSPACE_EXPANSIONS {
                    // No cspace ntfn or max expansions reached — fall back to
                    // blocking expansion via procmgr EP if available.
                    // Release SLOT_LOCK, expand via blocking RPC, reacquire.
                    // Caller (slot_alloc_async) will release SLOT_LOCK after we return.
                    return try_blocking_cspace_expand();
                }
                // Ensure root_bits is known for depth-aware probing
                ensure_root_bits(state);

                // Signal procmgr's bound notification for CSpace expansion
                syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
                state.expand_state = ExpandState::Requested;
                SlotResult::WouldBlock
            }
            ExpandState::Requested => {
                // Probe: try copying a known cap into the first slot of the
                // expected sub-CNode. If the sub-CNode exists, the copy
                // succeeds. We then delete the probe cap and register the
                // new segment.
                let probe_root_slot = CSPACE_EXPAND_BASE + state.cspace_expand_count as u64;
                let expanded_depth = state.root_bits + SLOT_EXPAND_BITS_DEFAULT as u8;
                let probe_addr = probe_root_slot << SLOT_EXPAND_BITS_DEFAULT;

                let err = invoke::cnode_copy_depth(
                    CAP_SELF_CSPACE, CAP_SELF_TCB,
                    CAP_SELF_CSPACE, probe_addr,
                    CAP_RIGHTS_ALL,
                    0, expanded_depth,
                );
                if err == 0 {
                    // Sub-CNode exists — clean up probe cap
                    invoke::cnode_delete_depth(
                        CAP_SELF_CSPACE, probe_addr, expanded_depth,
                    );

                    let base = probe_addr;
                    let count = 1u64 << SLOT_EXPAND_BITS_DEFAULT;

                    if state.seg_count >= MAX_SEGMENTS {
                        state.expand_state = ExpandState::Failed;
                        return SlotResult::Exhausted;
                    }

                    let si = state.seg_count;
                    state.segments[si] = Segment { base, count, next: 0 };
                    state.seg_count += 1;
                    state.active_seg = si;
                    state.cspace_expand_count += 1;
                    state.expand_state = ExpandState::Idle;

                    if state.root_bits > 0 {
                        state.expanded_depth = expanded_depth;
                    }

                    crate::udebug!(|_lb| {
                        _lb.str(b"[SLOT] cspace-expand: probed base=");
                        _lb.hex(base);
                        _lb.str(b" count=");
                        _lb.hex(count);
                        _lb.str(b" (seg ");
                        _lb.hex(si as u64);
                        _lb.str(b")\n");
                    });

                    // Allocate from the new segment
                    let seg = &mut state.segments[si];
                    let slot = seg.base + seg.next;
                    seg.next += 1;
                    SlotResult::Ok(slot)
                } else {
                    // Not ready yet — re-signal (idempotent: OR same badge bit)
                    syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
                    SlotResult::WouldBlock
                }
            }
            ExpandState::Failed => {
                SlotResult::Exhausted
            }
        }
    }
}

/// Allocate `count` consecutive CNode slots from the pool (synchronous path).
///
/// Returns the base slot index, or `None` if no segment has enough contiguous
/// room and a blocking CSpace expansion request fails.
///
/// Uses a local scan index to avoid advancing `active_seg` past partially-used
/// segments (which would permanently waste their remaining slots for future
/// `slot_alloc()` calls).
pub fn slot_alloc_consecutive(count: u64) -> Option<Cap> {
    if !slot_alloc_is_initialized() || count == 0 {
        return None;
    }
    for _ in 0..MAX_SEGMENTS + 2 {
        slot_lock_acquire();
        // SAFETY: SLOT_LOCK held
        let result = unsafe { slot_alloc_consecutive_fast(count) };
        slot_lock_release();
        if let Some(cap) = result {
            return Some(cap);
        }
        // All segments exhausted — expand without holding SLOT_LOCK
        let ep = unsafe { get_expand_ep() };
        if !try_expand(ep) {
            return None;
        }
    }
    None
}

/// Fast path: scan segments for consecutive slots. No blocking calls.
///
/// # Safety
/// Must be called with SLOT_LOCK held.
unsafe fn slot_alloc_consecutive_fast(count: u64) -> Option<Cap> {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized || count == 0 {
            return None;
        }
        // Scan from active_seg forward using a LOCAL index.
        // Do NOT modify state.active_seg — a segment with <count remaining
        // slots may still have room for single slot_alloc() calls.
        let mut scan = state.active_seg;
        while scan < state.seg_count {
            let seg = &mut state.segments[scan];
            if count <= seg.count && seg.next <= seg.count - count {
                let base = seg.base + seg.next;
                seg.next += count;
                return Some(base);
            }
            scan += 1;
        }
        None
    }
}

/// Allocate a single CNode slot from the pool (synchronous path).
///
/// Returns the absolute CNode slot index, or `None` if the pool is exhausted
/// or a blocking CSpace expansion request fails.
pub fn slot_alloc() -> Option<Cap> {
    if !slot_alloc_is_initialized() {
        return None;
    }
    for _ in 0..MAX_SEGMENTS + 2 {
        slot_lock_acquire();
        // SAFETY: SLOT_LOCK held
        let result = unsafe { slot_alloc_fast() };
        slot_lock_release();
        if let Some(cap) = result {
            return Some(cap);
        }
        // All segments exhausted — expand without holding SLOT_LOCK
        let ep = unsafe { get_expand_ep() };
        if !try_expand(ep) {
            return None;
        }
    }
    None
}

/// Fast path: scan segments for an available slot. No blocking calls.
///
/// # Safety
/// Must be called with SLOT_LOCK held.
unsafe fn slot_alloc_fast() -> Option<Cap> {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized {
            return None;
        }
        while state.active_seg < state.seg_count {
            let seg = &mut state.segments[state.active_seg];
            if seg.next < seg.count {
                let slot = seg.base + seg.next;
                seg.next += 1;
                return Some(slot);
            }
            state.active_seg += 1;
        }
        None
    }
}

// ===========================================================================
// CSpace expansion protocol helpers
// ===========================================================================

/// Ensure root_bits is populated (lazy query on first expansion).
fn ensure_root_bits(state: &mut SlotAllocState) {
    if state.root_bits == 0 {
        let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
        if info.error == 0 {
            unsafe {
                let ctx = crate::current_ipc_ctx();
                if !(*ctx).ipc_buffer.is_null() {
                    state.root_bits = (*(*ctx).ipc_buffer).msg[2] as u8;
                }
            }
        }
    }
}

/// Fallback: synchronous blocking CSpace expansion via procmgr EP.
/// Used when cspace_ntfn is unavailable or max async expansions are reached.
///
/// Releases SLOT_LOCK before the blocking RPC to avoid holding a spinlock
/// during IPC. Uses the EXPANDING guard to serialize concurrent expansions.
/// Reacquires SLOT_LOCK before returning (caller expects it held).
fn try_blocking_cspace_expand() -> SlotResult {
    // Read ep before releasing lock
    let ep = unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        if state.procmgr_ep != 0 { state.procmgr_ep } else { CAP_PROCMGR_EP }
    };

    // Release SLOT_LOCK before blocking RPC
    slot_lock_release();

    use core::sync::atomic::Ordering;
    if EXPANDING.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        // Another thread is expanding — yield and retry via WouldBlock
        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        slot_lock_acquire();
        return SlotResult::WouldBlock;
    }
    let result = request_expand_blocking(ep);
    EXPANDING.store(false, Ordering::Release);

    // Reacquire SLOT_LOCK to register the segment and allocate
    slot_lock_acquire();

    match result {
        Some((base, count)) => {
            // SAFETY: SLOT_LOCK held
            if unsafe { register_new_segment(base, count, b"async-fallback") } {
                // Allocate from the new segment
                unsafe {
                    let state = &mut *(&raw mut SLOT_ALLOC);
                    let si = state.seg_count - 1;
                    let seg = &mut state.segments[si];
                    let slot = seg.base + seg.next;
                    seg.next += 1;
                    SlotResult::Ok(slot)
                }
            } else {
                SlotResult::Exhausted
            }
        }
        None => {
            unsafe {
                let state = &mut *(&raw mut SLOT_ALLOC);
                state.expand_state = ExpandState::Failed;
            }
            SlotResult::Exhausted
        }
    }
}

/// Perform blocking PM_EXPAND_CSPACE Call and return the new segment.
fn request_expand_blocking(ep: Cap) -> Option<(Cap, u64)> {
    unsafe {
        let mut msg = crate::types::TronaMsg::zeroed();
        let mut reply = crate::types::TronaMsg::zeroed();
        msg.label = PM_EXPAND_CSPACE;
        msg.length = 1;
        msg.regs[0] = SLOT_EXPAND_BITS_DEFAULT;

        let err = ipc::call_ctx(
            crate::current_ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK || reply.length < 2 {
            return None;
        }

        let base = reply.regs[0];
        let count = reply.regs[1];
        if base == 0 || count == 0 {
            None
        } else {
            Some((base, count))
        }
    }
}

/// Cache the expanded CSpace depth used by depth-aware invoke helpers.
fn update_expansion_depth(state: &mut SlotAllocState) {
    if state.root_bits == 0 {
        let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
        if info.error == 0 {
            unsafe {
                let ctx = crate::current_ipc_ctx();
                if !(*ctx).ipc_buffer.is_null() {
                    state.root_bits = (*(*ctx).ipc_buffer).msg[2] as u8;
                }
            }
        }
    }
    if state.root_bits > 0 {
        state.expanded_depth = state.root_bits + SLOT_EXPAND_BITS_DEFAULT as u8;
    }
}
