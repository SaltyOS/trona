//! Per-process dynamic capability slot allocator
//!
//! Provides a bump allocator over a chained array of CNode slot segments.
//! The initial segment is assigned by procmgr/init at spawn time. When all
//! segments are exhausted, an expansion protocol requests more slots via
//! CSpace expansion (Signal+probe to procmgr's bound notification).
//!
//! The initial allocator range is communicated through the startup CSpace
//! layout descriptor (`AT_TRONA_CSPACE_LAYOUT`) as `[alloc_base, alloc_limit)`.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::invoke;
use crate::syscall::syscall;
use crate::types::Cap;

// Standard child CSpace layout
const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_CSPACE: u64 = 2;

const SLOT_EXPAND_BITS_DEFAULT: u64 = 10;
const MAX_SEGMENTS: usize = 16;
const MAX_SEGMENT_SLOTS: usize = 4096;
const SEGMENT_BITMAP_WORDS: usize = MAX_SEGMENT_SLOTS / 64;

/// A contiguous range of CNode slots available for allocation.
#[derive(Clone, Copy)]
struct Segment {
    base: Cap,
    count: u64,
    alloc_hint: u64,
    used: u64,
    bits: [u64; SEGMENT_BITMAP_WORDS],
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

#[derive(Clone, Copy, PartialEq)]
enum ExpandProgress {
    Completed,
    Pending,
    Failed,
}

/// Internal state for the per-process slot allocator.
struct SlotAllocState {
    segments: [Segment; MAX_SEGMENTS],
    seg_count: usize,
    active_seg: usize,
    initialized: bool,
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
    segments: [Segment {
        base: 0,
        count: 0,
        alloc_hint: 0,
        used: 0,
        bits: [0; SEGMENT_BITMAP_WORDS],
    }; MAX_SEGMENTS],
    seg_count: 0,
    active_seg: 0,
    initialized: false,
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
    while SLOT_LOCK
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while SLOT_LOCK.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
}

#[inline]
fn slot_lock_release() {
    SLOT_LOCK.store(0, core::sync::atomic::Ordering::Release);
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
        if count as usize > MAX_SEGMENT_SLOTS {
            state.expand_state = ExpandState::Failed;
            return false;
        }

        let si = state.seg_count;
        state.segments[si] = Segment {
            base,
            count,
            alloc_hint: 0,
            used: 0,
            bits: [0; SEGMENT_BITMAP_WORDS],
        };
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

/// Initialize the per-process slot allocator.
///
/// Called during process startup (from CRT or RTLD) with the initial
/// allocator range. `base==0` or `count==0` means "not provided".
/// `cspace_ntfn` is the notification cap for CSpace expansion signaling
/// (from AT_TRONA_CSPACE_NTFN auxv), or 0 if not available.
///
/// # Safety
/// Must be called exactly once during process initialization.
pub unsafe fn slot_alloc_init(base: Cap, count: u64, cspace_ntfn: u64) {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        for seg in &mut state.segments {
            *seg = Segment {
                base: 0,
                count: 0,
                alloc_hint: 0,
                used: 0,
                bits: [0; SEGMENT_BITMAP_WORDS],
            };
        }
        state.seg_count = 0;
        state.active_seg = 0;
        state.cspace_ntfn = cspace_ntfn;
        state.expand_state = ExpandState::Idle;
        state.root_bits = 0;
        state.expanded_depth = 0;
        state.cspace_expand_count = 0;

        let mut next_base = base;
        let mut remaining = count;
        if remaining == 0 && base != 0 {
            state.segments[0] = Segment {
                base,
                count: 0,
                alloc_hint: 0,
                used: 0,
                bits: [0; SEGMENT_BITMAP_WORDS],
            };
            state.seg_count = 1;
        }
        while remaining != 0 && state.seg_count < MAX_SEGMENTS {
            let chunk = core::cmp::min(remaining, MAX_SEGMENT_SLOTS as u64);
            let si = state.seg_count;
            state.segments[si] = Segment {
                base: next_base,
                count: chunk,
                alloc_hint: 0,
                used: 0,
                bits: [0; SEGMENT_BITMAP_WORDS],
            };
            state.seg_count += 1;
            next_base += chunk;
            remaining -= chunk;
        }

        state.initialized = remaining == 0 && (count != 0 || base != 0);
        if !state.initialized {
            state.seg_count = 0;
        }
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
        if state.seg_count > 0 {
            state.segments[0].base
        } else {
            0
        }
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
        for i in 0..state.seg_count {
            remaining += state.segments[i]
                .count
                .saturating_sub(state.segments[i].used);
        }
        remaining
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

/// Return the invoke depth required for a slot address in the current CSpace.
///
/// Flat root slots return 0. Expanded sub-CNode addresses return the observed
/// expanded depth once the allocator has successfully probed at least one
/// expansion segment.
pub fn slot_invoke_depth(slot: Cap) -> u8 {
    let depth = observed_cspace_depth();
    if depth == 0 {
        return 0;
    }

    if (slot >> SLOT_EXPAND_BITS_DEFAULT) >= CSPACE_EXPAND_BASE {
        depth
    } else {
        0
    }
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
        if let Some(slot) = alloc_single_locked(state) {
            return SlotResult::Ok(slot);
        }

        // All segments exhausted — enter CSpace expansion protocol.
        // Uses Signal+probe: signal the procmgr's bound notification, then
        // probe the deterministic root CNode slot to detect when the sub-CNode
        // has been placed there by the procmgr.
        let ntfn = state.cspace_ntfn;

        match state.expand_state {
            ExpandState::Idle => {
                if ntfn == 0 || state.cspace_expand_count >= MAX_CSPACE_EXPANSIONS {
                    return SlotResult::Exhausted;
                }
                // Ensure root_bits is known for depth-aware probing
                ensure_root_bits(state);

                // Signal procmgr's bound notification for CSpace expansion
                syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
                state.expand_state = ExpandState::Requested;
                SlotResult::WouldBlock
            }
            ExpandState::Requested => match poll_requested_expand_locked(state, ntfn) {
                ExpandProgress::Completed => match alloc_single_locked(state) {
                    Some(slot) => SlotResult::Ok(slot),
                    None => SlotResult::Exhausted,
                },
                ExpandProgress::Pending => SlotResult::WouldBlock,
                ExpandProgress::Failed => SlotResult::Exhausted,
            },
            ExpandState::Failed => SlotResult::Exhausted,
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
        if !drive_cspace_expand_blocking() {
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
        for off in 0..state.seg_count {
            let idx = (state.active_seg + off) % state.seg_count;
            if let Some(base) = segment_alloc_contiguous(&mut state.segments[idx], count) {
                state.active_seg = idx;
                return Some(base);
            }
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
        if !drive_cspace_expand_blocking() {
            return None;
        }
    }
    None
}

/// Allocate a single CNode slot from already-registered segments only.
///
/// Unlike `slot_alloc()`, this never triggers CSpace expansion. Callers that
/// must not recurse into procmgr from a server handler can use this to fail
/// fast on local slot exhaustion.
pub fn slot_alloc_no_expand() -> Option<Cap> {
    if !slot_alloc_is_initialized() {
        return None;
    }
    slot_lock_acquire();
    let result = unsafe { slot_alloc_fast() };
    slot_lock_release();
    result
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
        alloc_single_locked(state)
    }
}

pub fn slot_free(slot: Cap) -> bool {
    slot_lock_acquire();
    let ok = unsafe { slot_free_locked(slot) };
    slot_lock_release();
    ok
}

pub fn slot_free_range(base: Cap, count: u64) {
    if count == 0 {
        return;
    }
    slot_lock_acquire();
    unsafe {
        let mut off = 0u64;
        while off < count {
            let _ = slot_free_locked(base + off);
            off += 1;
        }
    }
    slot_lock_release();
}

unsafe fn slot_free_locked(slot: Cap) -> bool {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized {
            return false;
        }
        for idx in 0..state.seg_count {
            let seg = &mut state.segments[idx];
            if let Some(slot_idx) = segment_slot_index(seg, slot) {
                if segment_free(seg, slot_idx) {
                    if idx < state.active_seg {
                        state.active_seg = idx;
                    }
                    return true;
                }
                return false;
            }
        }
        false
    }
}

fn segment_slot_index(seg: &Segment, slot: Cap) -> Option<usize> {
    if slot < seg.base {
        return None;
    }
    let idx = slot - seg.base;
    if idx >= seg.count {
        return None;
    }
    Some(idx as usize)
}

fn segment_is_used(seg: &Segment, idx: usize) -> bool {
    let word = idx / 64;
    let bit = idx % 64;
    (seg.bits[word] & (1u64 << bit)) != 0
}

fn segment_mark_used(seg: &mut Segment, idx: usize) {
    let word = idx / 64;
    let bit = idx % 64;
    seg.bits[word] |= 1u64 << bit;
    seg.used += 1;
}

fn segment_mark_free(seg: &mut Segment, idx: usize) {
    let word = idx / 64;
    let bit = idx % 64;
    seg.bits[word] &= !(1u64 << bit);
    seg.used = seg.used.saturating_sub(1);
}

fn segment_alloc_single(seg: &mut Segment) -> Option<Cap> {
    if seg.used >= seg.count {
        return None;
    }
    let count = seg.count as usize;
    let start = (seg.alloc_hint as usize).min(count);
    for idx in start..count {
        if !segment_is_used(seg, idx) {
            segment_mark_used(seg, idx);
            seg.alloc_hint = (idx + 1) as u64;
            return Some(seg.base + idx as u64);
        }
    }
    for idx in 0..start {
        if !segment_is_used(seg, idx) {
            segment_mark_used(seg, idx);
            seg.alloc_hint = (idx + 1) as u64;
            return Some(seg.base + idx as u64);
        }
    }
    None
}

fn segment_alloc_contiguous(seg: &mut Segment, count: u64) -> Option<Cap> {
    if count == 0 || count > seg.count.saturating_sub(seg.used) {
        return None;
    }
    if count == 1 {
        return segment_alloc_single(seg);
    }

    let count_usize = count as usize;
    let limit = seg.count as usize;
    let mut run_start = 0usize;
    let mut run_len = 0usize;
    for idx in 0..limit {
        if !segment_is_used(seg, idx) {
            if run_len == 0 {
                run_start = idx;
            }
            run_len += 1;
            if run_len == count_usize {
                for mark in run_start..(run_start + count_usize) {
                    segment_mark_used(seg, mark);
                }
                seg.alloc_hint = (run_start + count_usize) as u64;
                return Some(seg.base + run_start as u64);
            }
        } else {
            run_len = 0;
        }
    }
    None
}

fn segment_free(seg: &mut Segment, idx: usize) -> bool {
    if idx >= seg.count as usize || !segment_is_used(seg, idx) {
        return false;
    }
    segment_mark_free(seg, idx);
    if idx as u64 <= seg.alloc_hint {
        seg.alloc_hint = idx as u64;
    }
    true
}

fn alloc_single_locked(state: &mut SlotAllocState) -> Option<Cap> {
    if state.seg_count == 0 {
        return None;
    }
    for off in 0..state.seg_count {
        let idx = (state.active_seg + off) % state.seg_count;
        if let Some(slot) = segment_alloc_single(&mut state.segments[idx]) {
            state.active_seg = idx;
            return Some(slot);
        }
    }
    None
}

// ===========================================================================
// CSpace expansion protocol helpers
// ===========================================================================

unsafe fn poll_requested_expand_locked(state: &mut SlotAllocState, ntfn: Cap) -> ExpandProgress {
    unsafe {
        let probe_root_slot = CSPACE_EXPAND_BASE + state.cspace_expand_count as u64;
        let expanded_depth = state.root_bits + SLOT_EXPAND_BITS_DEFAULT as u8;
        let probe_addr = probe_root_slot << SLOT_EXPAND_BITS_DEFAULT;

        let err = invoke::cnode_copy_depth(
            CAP_SELF_CSPACE,
            CAP_SELF_TCB,
            CAP_SELF_CSPACE,
            probe_addr,
            CAP_RIGHTS_ALL,
            0,
            expanded_depth,
        );
        if err != 0 {
            if ntfn != 0 {
                syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
            }
            return ExpandProgress::Pending;
        }

        invoke::cnode_delete_depth(CAP_SELF_CSPACE, probe_addr, expanded_depth);

        let base = probe_addr;
        let count = 1u64 << SLOT_EXPAND_BITS_DEFAULT;

        if state.seg_count >= MAX_SEGMENTS {
            state.expand_state = ExpandState::Failed;
            return ExpandProgress::Failed;
        }

        let si = state.seg_count;
        state.segments[si] = Segment {
            base,
            count,
            alloc_hint: 0,
            used: 0,
            bits: [0; SEGMENT_BITMAP_WORDS],
        };
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

        ExpandProgress::Completed
    }
}

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

fn drive_cspace_expand_blocking() -> bool {
    loop {
        slot_lock_acquire();
        let progress = unsafe {
            let state = &mut *(&raw mut SLOT_ALLOC);
            if !state.initialized {
                ExpandProgress::Failed
            } else {
                let ntfn = state.cspace_ntfn;
                if ntfn != 0 && state.cspace_expand_count < MAX_CSPACE_EXPANSIONS {
                    ensure_root_bits(state);
                    match state.expand_state {
                        ExpandState::Idle => {
                            syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
                            state.expand_state = ExpandState::Requested;
                            ExpandProgress::Pending
                        }
                        ExpandState::Requested => poll_requested_expand_locked(state, ntfn),
                        ExpandState::Failed => ExpandProgress::Failed,
                    }
                } else {
                    slot_lock_release();
                    return false;
                }
            }
        };
        slot_lock_release();

        match progress {
            ExpandProgress::Completed => return true,
            ExpandProgress::Pending => {
                syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
            ExpandProgress::Failed => return false,
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
