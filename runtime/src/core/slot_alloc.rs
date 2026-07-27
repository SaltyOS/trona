//! Per-process dynamic capability slot allocator
//!
//! Provides a bump allocator over a chained array of CNode slot segments.
//! The initial segment is assigned by init at spawn time via the startup
//! CSpace layout descriptor. When all segments are exhausted, the allocator
//! drives synchronous self-expansion: either an in-process retype path that
//! calls `RSRC_ALLOC(OBJ_CNODE)` against rsrcsrv, or a carve-out handler
//! installed by [`install_expand_handler`] (rsrcsrv itself uses a handler
//! that retypes from its own untyped pool to avoid IPC recursion).
//!
//! The initial allocator envelope is communicated through the startup CSpace
//! layout descriptor (`SaltyOSStartupLayoutV1.cspace_layout_ptr`) as
//! `[alloc_base, alloc_limit)`, with reserved holes such as the expansion and
//! receive windows subtracted before segments are registered.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::core::server_consts::{CSPACE_EXPAND_BASE, MAX_CSPACE_EXPANSIONS};
use trona_kernel::core_types::{Cap, CapRef, SaltyOSCspaceLayoutV1};
use trona_kernel::invoke;
use trona_protocol::common::TRONA_OK;
use trona_protocol::rsrcsrv::RSRC_ALLOC;

const OBJ_CNODE: u64 = uapi::KERNITE_OBJ_CNODE as u64;

// Standard child CSpace layout
const CAP_SELF_CSPACE: CapRef = CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64);

const SLOT_EXPAND_BITS_DEFAULT: u64 = 10;
const MAX_SEGMENTS: usize = 80;
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

#[derive(Clone, Copy, PartialEq)]
pub enum ExpandProgress {
    Completed,
    Pending,
    Failed,
}

/// Kernel-side CSpace install plan for an external self-expansion handler.
///
/// The handler owns object creation and `cnode_move`; `slot_alloc` owns the
/// deterministic expansion window and segment accounting. Splitting the two
/// keeps rsrcsrv's no-IPC carve-out on the same allocator state machine as the
/// normal `RSRC_ALLOC(OBJ_CNODE)` path.
#[derive(Clone, Copy)]
pub struct ExternalExpandPlan {
    pub root_slot: Cap,
    pub packed_base: Cap,
    pub slot_count: u64,
    pub cnode_size_bits: u64,
}

/// Self-expansion handler signature. When installed via
/// [`install_expand_handler`], the allocator dispatches expansion through this
/// callback instead of running the in-process [`self_expand`] path. rsrcsrv
/// installs its own handler to bypass IPC recursion (it retypes `OBJ_CNODE`
/// directly from its local untyped pool instead of calling itself over IPC).
pub type ExpandHandler = unsafe fn(ExternalExpandPlan) -> ExpandProgress;

/// Internal state for the per-process slot allocator.
struct SlotAllocState {
    segments: [Segment; MAX_SEGMENTS],
    seg_count: usize,
    active_seg: usize,
    initialized: bool,
    /// Root CNode size_bits (populated from layout or `cnode_get_info`).
    root_bits: u8,
    /// Total CNode depth after expansion (root_bits + sub_bits), 0 if not expanded.
    expanded_depth: u8,
    /// Number of completed CSpace expansions (installed sub-CNodes).
    cspace_expand_count: usize,
    /// Root-CNode slots reserved for expansion sub-CNodes.
    expand_base: Cap,
    expand_limit: Cap,
    /// rsrcsrv authority endpoint used by [`self_expand`] for `RSRC_ALLOC`.
    /// 0 until [`enable_self_expand`] is invoked.
    runtime_authority_ep: Cap,
    /// Owner badge supplied to rsrcsrv for self-expansion accounting.
    runtime_owner_id: u64,
    /// Permanently-reserved slot used as the destination for `OBJ_CNODE`
    /// retypes during self-expansion. Sourced from a non-allocator-managed
    /// range so [`self_expand`] can reuse it without re-entering slot_alloc.
    /// `cnode_move` empties the slot after each install, leaving it ready
    /// for the next expansion.
    expand_temp_slot: Cap,
    /// Optional carve-out handler. When set, [`self_expand`] dispatches
    /// through this callback instead of running the in-process retype path.
    expand_handler: Option<ExpandHandler>,
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
    root_bits: 0,
    expanded_depth: 0,
    cspace_expand_count: 0,
    expand_base: 0,
    expand_limit: 0,
    runtime_authority_ep: 0,
    runtime_owner_id: 0,
    expand_temp_slot: 0,
    expand_handler: None,
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

fn reset_state(state: &mut SlotAllocState) {
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
    state.initialized = false;
    state.root_bits = 0;
    state.expanded_depth = 0;
    state.cspace_expand_count = 0;
    state.expand_base = 0;
    state.expand_limit = 0;
    state.runtime_authority_ep = 0;
    state.runtime_owner_id = 0;
    state.expand_temp_slot = 0;
    state.expand_handler = None;
}

fn append_segment_locked(state: &mut SlotAllocState, base: Cap, count: u64) -> bool {
    if count as usize > MAX_SEGMENT_SLOTS || state.seg_count >= MAX_SEGMENTS {
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
    true
}

fn add_hole(
    holes: &mut [(u64, u64); 2],
    hole_count: &mut usize,
    range_base: u64,
    range_limit: u64,
    hole_base: u64,
    hole_limit: u64,
) {
    if *hole_count >= holes.len() || hole_limit <= hole_base {
        return;
    }
    let start = core::cmp::max(range_base, hole_base);
    let end = core::cmp::min(range_limit, hole_limit);
    if end <= start {
        return;
    }
    holes[*hole_count] = (start, end);
    *hole_count += 1;
}

fn append_expected_range(
    out: &mut [(u64, u64); MAX_SEGMENTS],
    out_count: &mut usize,
    mut base: u64,
    mut count: u64,
) -> bool {
    while count != 0 {
        if *out_count >= MAX_SEGMENTS {
            return false;
        }
        let chunk = core::cmp::min(count, MAX_SEGMENT_SLOTS as u64);
        out[*out_count] = (base, chunk);
        *out_count += 1;
        base = base.saturating_add(chunk);
        count -= chunk;
    }
    true
}

fn collect_layout_segments(
    layout: &SaltyOSCspaceLayoutV1,
    frame_floor: u64,
) -> Option<([(u64, u64); MAX_SEGMENTS], usize)> {
    let total_slots = if layout.cnode_bits >= 63 {
        0
    } else {
        1u64 << layout.cnode_bits
    };
    let alloc_base = core::cmp::max(
        core::cmp::max(layout.alloc_base, layout.frame_slot_base),
        frame_floor,
    );
    let alloc_limit = core::cmp::min(layout.alloc_limit, total_slots);
    if alloc_limit <= alloc_base {
        return None;
    }

    let mut holes = [(0u64, 0u64); 2];
    let mut hole_count = 0usize;
    add_hole(
        &mut holes,
        &mut hole_count,
        alloc_base,
        alloc_limit,
        layout.expand_base,
        layout.expand_limit,
    );
    add_hole(
        &mut holes,
        &mut hole_count,
        alloc_base,
        alloc_limit,
        layout.recv_base,
        layout.recv_limit,
    );
    if hole_count == 2 && holes[1].0 < holes[0].0 {
        let tmp = holes[0];
        holes[0] = holes[1];
        holes[1] = tmp;
    }

    let mut segments = [(0u64, 0u64); MAX_SEGMENTS];
    let mut segment_count = 0usize;
    let mut cursor = alloc_base;
    let mut i = 0usize;
    while i < hole_count {
        let (hole_base, hole_limit) = holes[i];
        if cursor < hole_base
            && !append_expected_range(
                &mut segments,
                &mut segment_count,
                cursor,
                hole_base - cursor,
            )
        {
            return None;
        }
        if cursor < hole_limit {
            cursor = hole_limit;
        }
        i += 1;
    }
    if cursor < alloc_limit
        && !append_expected_range(
            &mut segments,
            &mut segment_count,
            cursor,
            alloc_limit - cursor,
        )
    {
        return None;
    }
    (segment_count != 0).then_some((segments, segment_count))
}

fn append_layout_segments_locked(
    state: &mut SlotAllocState,
    layout: &SaltyOSCspaceLayoutV1,
    frame_floor: u64,
) -> bool {
    let Some((segments, count)) = collect_layout_segments(layout, frame_floor) else {
        return false;
    };
    let mut i = 0usize;
    while i < count {
        if !append_segment_locked(state, segments[i].0, segments[i].1) {
            return false;
        }
        i += 1;
    }
    true
}

/// Initialize the per-process slot allocator.
///
/// Called during process startup (from CRT or RTLD) with the initial
/// allocator range. `base==0` or `count==0` means "not provided".
/// Self-expansion is enabled separately via [`enable_self_expand`] once the
/// rsrcsrv authority endpoint is available.
///
/// # Safety
/// Must be called exactly once during process initialization.
pub unsafe fn slot_alloc_init(base: Cap, count: u64) {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        reset_state(state);

        let mut next_base = base;
        let mut remaining = count;
        if remaining == 0 && base != 0 {
            let _ = append_segment_locked(state, base, 0);
        }
        while remaining != 0 {
            let chunk = core::cmp::min(remaining, MAX_SEGMENT_SLOTS as u64);
            if !append_segment_locked(state, next_base, chunk) {
                break;
            }
            next_base += chunk;
            remaining -= chunk;
        }

        state.initialized = remaining == 0 && (count != 0 || base != 0);
        if !state.initialized {
            state.seg_count = 0;
        }
    }
}

/// Initialize the slot allocator from a startup CSpace layout, subtracting
/// reserved holes (`expand` and `recv`) from the allocator envelope.
///
/// Returns `false` if the layout does not leave any usable slot segment or the
/// configured segment table is too small for the envelope.
///
/// # Safety
/// Must be called exactly once during process initialization.
pub unsafe fn slot_alloc_init_from_layout(
    layout: &SaltyOSCspaceLayoutV1,
    frame_floor: u64,
) -> bool {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        reset_state(state);
        if layout.has_expand_range() {
            state.expand_base = layout.expand_base;
            state.expand_limit = layout.expand_limit;
        }
        if layout.cnode_bits <= u8::MAX as u64 {
            state.root_bits = layout.cnode_bits as u8;
        }

        if !append_layout_segments_locked(state, layout, frame_floor) {
            reset_state(state);
            return false;
        }
        state.initialized = true;
        true
    }
}

/// Check whether the slot allocator has been initialized.
pub fn slot_alloc_is_initialized() -> bool {
    unsafe { (*(&raw const SLOT_ALLOC)).initialized }
}

/// Cheap state snapshot for diagnostics. Returns
/// `(remaining_slots, runtime_authority_ep_nonzero,
/// expand_handler_installed, cspace_expand_count,
/// expand_base, expand_limit)`. Called from `fatal_slot_alloc`
/// so the log line names the cause of the hang.
pub fn expansion_state() -> (u64, bool, bool, usize, Cap, Cap) {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        (
            slot_alloc_remaining(),
            state.runtime_authority_ep != 0,
            state.expand_handler.is_some(),
            state.cspace_expand_count,
            state.expand_base,
            state.expand_limit,
        )
    }
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
///
/// This is not necessarily a contiguous range with `slot_alloc_base()` when the
/// startup layout contains reserved holes.
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

/// Verify that the initialized allocator segments match the usable slot
/// segments derived from `layout` after reserved holes are subtracted.
pub fn slot_alloc_matches_layout(layout: &SaltyOSCspaceLayoutV1, frame_floor: u64) -> bool {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        if !state.initialized {
            return false;
        }
        let Some((expected, expected_count)) = collect_layout_segments(layout, frame_floor) else {
            return false;
        };
        if state.seg_count != expected_count {
            return false;
        }
        let mut i = 0usize;
        while i < expected_count {
            if state.segments[i].base != expected[i].0 || state.segments[i].count != expected[i].1 {
                return false;
            }
            i += 1;
        }
        true
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
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        if state.expanded_depth == 0
            || state.cspace_expand_count == 0
            || state.expand_limit <= state.expand_base
        {
            return 0;
        }

        let root_slot = slot >> SLOT_EXPAND_BITS_DEFAULT;
        let granted_limit = state
            .expand_base
            .saturating_add(state.cspace_expand_count as u64);
        if root_slot >= state.expand_base && root_slot < granted_limit {
            state.expanded_depth
        } else {
            0
        }
    }
}

/// Resolve a bare slot index into a depth-carrying [`CapRef`] by looking up
/// its invoke depth. This is the single place the implicit `slot_invoke_depth`
/// lookup belongs: the few boundaries that hold only a raw `u64` slot — a cap
/// just received into a sticky scratch slot, or a slot handed across an IPC
/// boundary with no owning handle. Where an `OwnedCap` / `OwnedSlot` /
/// `LeakedCapRef` is in hand, borrow the depth from it
/// (`borrow()` / `cap_ref()`) instead of resolving from scratch.
pub fn resolved_cap_ref(slot: Cap) -> CapRef {
    CapRef::at_depth(slot, slot_invoke_depth(slot))
}

fn max_expansions_locked(state: &SlotAllocState) -> usize {
    let span = state.expand_limit.saturating_sub(state.expand_base);
    core::cmp::min(span, MAX_CSPACE_EXPANSIONS as u64) as usize
}

/// Async slot allocation with self-healing expansion protocol.
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

        // All segments exhausted — drive a self-expansion attempt. Either
        // the in-process retype path or the rsrcsrv carve-out handler runs
        // synchronously, so async callers complete in one step here.
        if state.runtime_authority_ep == 0 && state.expand_handler.is_none() {
            return SlotResult::Exhausted;
        }
        if state.cspace_expand_count >= max_expansions_locked(state) {
            return SlotResult::Exhausted;
        }

        match self_expand_locked(state) {
            ExpandProgress::Completed => match alloc_single_locked(state) {
                Some(slot) => SlotResult::Ok(slot),
                None => SlotResult::Exhausted,
            },
            ExpandProgress::Pending => SlotResult::WouldBlock,
            ExpandProgress::Failed => SlotResult::Exhausted,
        }
    }
}

/// Allocate `count` consecutive CNode slots from the pool.
///
/// Returns the base slot index, or `None` if no segment has enough contiguous
/// room and self-expansion cannot install another sub-CNode (no authority
/// configured, or the per-process expansion ceiling is reached).
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
        if result.is_some() {
            slot_lock_release();
            return result;
        }
        // SAFETY: SLOT_LOCK still held; try one synchronous self-expansion.
        let progressed = unsafe { try_self_expand_locked() };
        slot_lock_release();
        if !progressed {
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

/// Allocate a single CNode slot from the pool.
///
/// Returns the absolute CNode slot index, or `None` if the pool is exhausted
/// and self-expansion cannot install another sub-CNode (no authority
/// configured, or the per-process expansion ceiling is reached).
pub fn slot_alloc() -> Option<Cap> {
    if !slot_alloc_is_initialized() {
        return None;
    }
    for _ in 0..MAX_SEGMENTS + 2 {
        slot_lock_acquire();
        // SAFETY: SLOT_LOCK held
        let result = unsafe { slot_alloc_fast() };
        if result.is_some() {
            slot_lock_release();
            return result;
        }
        // SAFETY: SLOT_LOCK still held; try one synchronous self-expansion.
        let progressed = unsafe { try_self_expand_locked() };
        slot_lock_release();
        if !progressed {
            return None;
        }
    }
    None
}

/// Reset the per-process slot allocator after a fork. The child has a
/// fresh CSpace whose segment positions are described by its own startup
/// layout, so the parent's segment table and expansion bookkeeping do
/// not apply. This empties the segment table, zeroes the expansion
/// counter, and tears down the self-expansion authority/temp/handler so
/// the child can re-establish them through the normal startup path
/// (`runtime_init_slot_allocator` followed by `enable_self_expand` /
/// `reserve_expand_temp_slot` if the child needs runtime expansion).
///
/// Must be called from the post-fork child entry (`_trona_post_fork_child`)
/// before any user-driven `slot_alloc` traffic resumes.
///
/// # Safety
/// Must run on the single fork-child thread, with no concurrent slot
/// allocation in flight.
pub unsafe fn slot_alloc_reset_for_fork() {
    slot_lock_acquire();
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        reset_state(state);
    }
    slot_lock_release();
}

/// Drive a single self-expansion attempt while holding `SLOT_LOCK`. Returns
/// `true` if a new segment was registered (callers should retry their fast
/// path), `false` if expansion is unavailable (no authority/handler) or the
/// per-process expansion ceiling is reached. Invariant violations inside
/// `self_expand_locked` are fatal and do not return.
///
/// # Safety
/// `SLOT_LOCK` must be held by the caller.
unsafe fn try_self_expand_locked() -> bool {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized {
            return false;
        }
        if state.runtime_authority_ep == 0 && state.expand_handler.is_none() {
            return false;
        }
        if state.cspace_expand_count >= max_expansions_locked(state) {
            return false;
        }
        matches!(self_expand_locked(state), ExpandProgress::Completed)
    }
}

/// Allocate a single CNode slot from already-registered segments only.
///
/// Unlike `slot_alloc()`, this never triggers CSpace expansion. Callers that
/// must not recurse into self-expansion — e.g. rsrcsrv's own carve-out
/// handler, which already holds `SLOT_LOCK` — can use this to fail fast on
/// local slot exhaustion.
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

/// Return an empty CNode slot index to the per-process allocator. Module-private:
/// the only safe path to releasing a slot is dropping its owning handle
/// (`OwnedSlot` / `OwnedCap` / `OwnedSlotRange` / the `Owned*` aggregates). The
/// cross-module raw escape is [`reclaim_empty_allocated_slot_unchecked`], which
/// wraps this and carries the safety obligation in its signature.
fn slot_free(slot: Cap) -> bool {
    slot_lock_acquire();
    let ok = unsafe { slot_free_locked(slot) };
    slot_lock_release();
    ok
}

/// Return an empty, globally-allocated CNode slot to the slot allocator by
/// raw handle — the unsafe escape for the few sites that cannot model the slot
/// as an `OwnedSlot` / `OwnedCap` (e.g. a slot whose cap teardown is entangled
/// with a domain allocator and must run before the index is reclaimed). Prefer
/// the owning handles, whose `Drop` reclaims the slot safely; reach for this
/// only when ownership genuinely cannot be expressed in the type system.
///
/// # Safety
/// - `slot` was handed out by this process's global slot allocator (`slot_alloc`
///   / `alloc_slot`) — not a `SlotPool` slot, nor a kernel-installed or
///   bootstrap-reserved slot.
/// - The slot is **empty** at the call: any capability it held has already been
///   deleted or revoked. This returns only the index, not a cap teardown.
/// - No live `OwnedSlot` / `OwnedCap` owns `slot`, and no other site frees it;
///   this runs exactly once for the slot.
pub unsafe fn reclaim_empty_allocated_slot_unchecked(slot: Cap) -> bool {
    slot_free(slot)
}

/// Mark a specific slot as permanently used in the current allocator pool.
///
/// Returns `true` when `slot` belonged to a registered segment and was free,
/// `false` otherwise.
pub fn slot_mark_used(slot: Cap) -> bool {
    slot_lock_acquire();
    let ok = unsafe { slot_mark_used_locked(slot) };
    slot_lock_release();
    ok
}

/// Mark a fixed CSpace range as unavailable to dynamic allocation.
///
/// Init uses this for kernel-installed and bootstrap-reserved root slots. If
/// the current layout has already excluded the range, slots outside registered
/// segments are ignored.
pub fn install_skip_range(base: Cap, count: u64) {
    if count == 0 {
        return;
    }
    slot_lock_acquire();
    unsafe {
        let mut off = 0u64;
        while off < count {
            let _ = slot_mark_used_locked(base + off);
            off += 1;
        }
    }
    slot_lock_release();
}

/// Tear down a self-CSpace slot handed out by this allocator and return it
/// to the pool, enforcing the invariant that **a slot's bitmap bit is only
/// released once its CNode entry is empty** — so the allocator can never
/// diverge from CNode occupancy.
///
/// `cnode_delete` is a single-cap deletion: derived caps are preserved by the
/// kernel's CDT re-rooting path. This helper never revokes descendants. Use an
/// explicit revoke/teardown path when authority withdrawal for a whole derived
/// subtree is intended.
///
/// If a prior IPC transfer already moved the cap out, `cnode_delete` reports
/// `NOT_FOUND`; the slot is empty, so the allocator index can still be
/// returned. Any other delete error leaves the bitmap bit set rather than
/// handing a potentially occupied slot to a later allocation.
///
/// # Safety
/// - `slot` is a global-allocator slot the caller owns exclusively. After this
///   the cap is gone and the index is returned to `slot_alloc` when the CNode
///   entry is known empty. No live `OwnedCap` / `OwnedSlot` may own `slot`, and
///   nothing else may free it: a second free clears the allocator bitmap bit
///   twice, so a later `slot_alloc` hands out an occupied index (kernel
///   `SlotOccupied` / cap aliasing).
pub unsafe fn delete_and_free(slot: Cap) {
    // SAFETY: caller guarantees exclusive ownership of `slot` (this fn's
    // `# Safety`); forward that obligation to the depth-carrying variant.
    unsafe { delete_and_free_depth(slot, slot_invoke_depth(slot)) };
}

/// `delete_and_free` for a slot whose CSpace invoke depth the caller already
/// holds (expansion sub-CNode slots). Flat root slots pass `depth = 0`.
///
/// # Safety
/// Same contract as [`delete_and_free`]; `depth` is `slot`'s CSpace invoke
/// depth.
pub unsafe fn delete_and_free_depth(slot: Cap, depth: u8) {
    if slot == 0 {
        return;
    }
    // SAFETY: caller owns `slot` exclusively (this fn's `# Safety`). Delete the
    // local cap only, then return the index once the CNode entry is known empty.
    let err = delete_slot_depth(slot, depth);
    if err == 0 || err == uapi::KERNITE_ERR_NOT_FOUND as i32 {
        slot_free(slot);
    }
}

/// Delete the cap in `slot` *without* returning the slot index to the global
/// allocator — for slots owned by a private
/// [`SlotPool`](crate::core::slot_pool::SlotPool), which has no reclaim path
/// and owns the index itself. Freeing it back to `slot_alloc` would corrupt
/// global accounting (the index was reserved out of the global pool for the
/// SlotPool); instead the index simply leaks within the pool, which is
/// acceptable for the pool's process-lifetime reservations.
///
/// # Safety
/// - `slot` (at invoke `depth`) holds a cap the caller is entitled to tear down,
///   with no live owner still relying on it. Unlike [`delete_and_free_depth`]
///   the index is NOT returned to the allocator (it belongs to a `SlotPool`);
///   calling this on a global-allocator slot leaks the index.
pub unsafe fn delete_depth(slot: Cap, depth: u8) {
    let _ = delete_slot_depth(slot, depth);
}

fn delete_slot_depth(slot: Cap, depth: u8) -> i32 {
    if slot == 0 {
        return 0;
    }
    invoke::cnode_delete_depth(CAP_SELF_CSPACE, slot, depth)
}
// ===========================================================================
// TransferCap — typed cap-transfer boundary.
// ===========================================================================

/// A capability staged for an outbound IPC cap transfer.
///
/// The kernel's MessagePipe cap transfer is **move**: a staged cap is
/// `take_ref`'d out of the sender's CSpace on a successful send (and
/// rolled back into the sender if the send fails). Sending a cap the
/// sender means to keep therefore silently loses it. `TransferCap` makes
/// that move explicit at the type level — a cap-sending helper accepts a
/// `TransferCap`, never a bare slot, so each cap-send site must state how
/// the cap reaches the wire:
///
/// - [`dup_for_transfer`] — the sender keeps a retained cap and puts a
///   throwaway copy on the wire. The original slot is untouched.
/// - [`move_for_transfer`] — the sender gives up a transient cap and its
///   slot along with it.
/// - [`forward_external`] — the cap rides out of a slot owned by
///   something else (e.g. a reactor's sticky receive-scratch slot); the
///   slot itself is left for its owner to rearm.
///
/// Not `Copy`: the staged slot is consumed once. On drop the owned slot
/// is reclaimed with [`delete_and_free`], which is correct
/// whether the send moved the cap out (empty slot → the index is freed)
/// or failed and rolled it back (cap present → deleted, then freed). A
/// `TransferCap` built but never sent is cleaned up the same way.
#[must_use = "a TransferCap holds a staged cap slot; pass it to a cap-sending helper or let it drop to reclaim the slot"]
pub struct TransferCap {
    cap: CapRef,
    owns_slot: bool,
}

impl TransferCap {
    /// The slot to stage into the outbound `caps[]` window. For use by a
    /// cap-sending helper immediately before the send.
    pub fn slot(&self) -> Cap {
        self.cap.addr()
    }
}

impl Drop for TransferCap {
    fn drop(&mut self) {
        if self.owns_slot && self.cap.addr() != 0 {
            // SAFETY: an owns_slot TransferCap is the sole owner of the slot (built
            // from a transient/duplicated cap via the unsafe constructors). After
            // a send moved the cap out the slot is empty; otherwise the cap is
            // still present. `delete_and_free_depth` handles both cases without
            // revoking descendants.
            // The invoke depth rides in the CapRef, so teardown needs no
            // slot_invoke_depth re-derivation.
            unsafe { delete_and_free_depth(self.cap.addr(), self.cap.depth()) };
        }
    }
}

/// Copy a **retained** cap into a fresh transient slot for a one-shot
/// transfer, narrowing the copy to `rights` (a `KERNITE_RIGHT_*` mask).
/// `retained` carries its own invoke depth; the original slot is left in
/// place — the caller keeps it live. Returns `None` on allocator or copy
/// failure. Use this to hand out a less-privileged copy than the retained
/// cap — e.g. a `READ|EXECUTE` exec MO derived from a fuller backing cap.
pub fn dup_for_transfer_with_rights(retained: CapRef, rights: u64) -> Option<TransferCap> {
    let temp = slot_alloc()?;
    // The destination is a fresh global-allocator slot, so its depth is
    // resolved here; the source depth rides in `retained`.
    let dst = CapRef::at_depth(temp, slot_invoke_depth(temp));
    if invoke::cnode_copy_ref(CAP_SELF_CSPACE, retained, CAP_SELF_CSPACE, dst, rights) != 0 {
        slot_free(temp);
        return None;
    }
    Some(TransferCap {
        cap: dst,
        owns_slot: true,
    })
}

/// Copy a **retained** cap into a fresh transient slot for a one-shot
/// transfer with the cap's full rights. See [`dup_for_transfer_with_rights`]
/// to narrow the copy. `retained` carries its own invoke depth; the original
/// slot is left in place. Returns `None` on allocator or copy failure.
pub fn dup_for_transfer(retained: CapRef) -> Option<TransferCap> {
    dup_for_transfer_with_rights(retained, uapi::KERNITE_RIGHT_ALL as u64)
}

/// Transfer a **transient** cap, giving up its slot. After the send the
/// slot is reclaimed (empty on success, or rolled-back-then-deleted on
/// failure).
///
/// # Safety
/// - `transient` is a global-allocator slot the caller owns exclusively and is
///   giving up; no live `OwnedCap` / `OwnedSlot` owns it. The returned
///   `TransferCap` reclaims the slot (after the send, or on drop if never sent),
///   so a second owner would double-free the index.
pub unsafe fn move_for_transfer(transient: CapRef) -> TransferCap {
    TransferCap {
        cap: transient,
        owns_slot: true,
    }
}

/// Transfer a cap out of a slot owned and recycled by something else
/// (e.g. a server reactor's sticky receive-scratch slot). The send moves
/// the cap out; the slot is left untouched for its owner to rearm.
///
/// # Safety
/// - `slot` is owned and rearmed by something else (a reactor's sticky
///   receive-scratch slot) — NOT a slot any live `OwnedCap` / `OwnedSlot` owns.
///   The send moves the cap out and the returned `TransferCap` does NOT free the
///   slot. Passing an `OwnedCap`'s slot here strands that owner over an empty
///   slot; the cap is also expected to be the caller's to move out.
pub unsafe fn forward_external(slot: CapRef) -> TransferCap {
    TransferCap {
        cap: slot,
        owns_slot: false,
    }
}

// ===========================================================================
// Owning capability handles.
// ===========================================================================

/// Where a slot's index came from — controls whether the index is returned to
/// the global allocator when its owning handle drops.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SlotOrigin {
    /// Allocated from the process-wide `slot_alloc`; the index is returned
    /// (`slot_free`) when the handle drops.
    Global,
    /// Allocated from a private [`SlotPool`](crate::core::slot_pool::SlotPool),
    /// which has no reclaim path: on drop the cap is deleted but the index is
    /// NOT returned to the global allocator (the pool, not `slot_alloc`, owns
    /// it). See [`delete_depth`].
    Pool,
}

/// An allocated CNode slot that does not (yet) hold a capability.
///
/// The slot allocator hands one of these out before a cap is installed —
/// a retype, copy, or IPC receive lands a cap into it. Move-only; on drop
/// the slot is returned to the allocator with [`slot_free`] and nothing
/// else, because an empty slot has no cap to tear down. Once a cap
/// occupies it, [`OwnedSlot::assume_filled`] converts to an [`OwnedCap`]
/// whose drop deletes the cap.
#[must_use = "an OwnedSlot owns an allocated CNode slot; bind it or let it drop to free the slot"]
pub struct OwnedSlot {
    slot: Cap,
    depth: u8,
}

impl OwnedSlot {
    /// The raw slot address — for arming a receive window or staging a
    /// retype destination. Does not consume the handle.
    pub fn addr(&self) -> Cap {
        self.slot
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Borrow as a [`CapRef`] addressing the slot.
    pub fn borrow(&self) -> CapRef {
        CapRef::at_depth(self.slot, self.depth)
    }

    /// Declare that a capability now occupies this slot (after a
    /// successful retype / copy / receive), yielding an [`OwnedCap`] whose
    /// drop deletes the cap. The empty-slot free is suppressed.
    pub fn assume_filled(self) -> OwnedCap {
        let (slot, depth) = (self.slot, self.depth);
        core::mem::forget(self);
        OwnedCap {
            slot,
            depth,
            origin: SlotOrigin::Global,
        }
    }

    /// Take the raw slot, suppressing the empty-slot free. The caller
    /// becomes responsible for the slot.
    #[must_use = "into_raw yields the raw slot and suppresses the empty-slot free; dropping it leaks the slot"]
    pub fn into_raw(self) -> Cap {
        let slot = self.slot;
        core::mem::forget(self);
        slot
    }
}

impl Drop for OwnedSlot {
    fn drop(&mut self) {
        if self.slot != 0 {
            slot_free(self.slot);
        }
    }
}

/// A capability the current process owns: a CNode slot holding a live cap.
///
/// Move-only; on drop the cap is torn down and the slot returned to the
/// allocator via [`delete_and_free_depth`]. `OwnedCap` covers
/// only the *local* cap teardown — a cap allocated through rsrcsrv carries
/// a separate `record_id` that must be released with `free_record` on an
/// explicit teardown path, never from `Drop` (which can run under locks /
/// during unwind and must not issue IPC). For rsrcsrv-minted objects,
/// prefer [`OwnedRecordedCap`] (or [`OwnedMpPair`] for a pipe pair), which
/// bind the cap(s) and the record into one owner whose `release` frees
/// both.
#[must_use = "an OwnedCap owns a capability; borrow/transfer/duplicate it or let it drop to release it"]
pub struct OwnedCap {
    slot: Cap,
    depth: u8,
    origin: SlotOrigin,
}

impl OwnedCap {
    /// Adopt exclusive ownership of a slot by raw index — e.g. a cap just
    /// received into a slot the caller now owns, or a freshly allocated slot
    /// about to be retyped/moved into. The caller must not release this slot by
    /// any other route afterward.
    ///
    /// # Safety
    /// - `slot` (at invoke `depth`) is a slot this process owns exclusively: no
    ///   other `OwnedCap` / `OwnedSlot` owns the index and nothing else frees it.
    ///   The slot may already hold a cap or be empty and about to be filled (a
    ///   retype/move lands a cap into it) — the returned `OwnedCap` is the sole
    ///   teardown either way (Drop deletes any cap present, a no-op when empty,
    ///   and returns the index to `slot_alloc` exactly once).
    pub unsafe fn from_raw(slot: Cap, depth: u8) -> Self {
        Self {
            slot,
            depth,
            origin: SlotOrigin::Global,
        }
    }

    /// Adopt a slot with an explicit [`SlotOrigin`] — used when the slot was
    /// allocated from a private [`SlotPool`] (`SlotOrigin::Pool`) instead of
    /// the global allocator, so its drop deletes the cap without returning the
    /// index to `slot_alloc`.
    ///
    /// # Safety
    /// - Same exclusive-ownership contract as [`from_raw`](Self::from_raw).
    /// - `origin` matches where the index was allocated: `Global` returns it to
    ///   `slot_alloc` on drop; `Pool` deletes the cap only and leaves the index
    ///   to the owning `SlotPool`.
    pub unsafe fn from_raw_in(slot: Cap, depth: u8, origin: SlotOrigin) -> Self {
        Self {
            slot,
            depth,
            origin,
        }
    }

    /// The null (slot 0) capability — a non-owning placeholder for a bare
    /// `OwnedCap` field before a real cap is installed, and for `const`
    /// empty-slot sentinels (it is a `const fn`, so it works in a
    /// `const EMPTY: Self = ...` slab/arena sentinel). Drop is a no-op
    /// (the slot is 0), [`borrow`](Self::borrow) yields `CapRef::NULL`, and
    /// [`as_raw`](Self::as_raw) is 0. Overwrite it with a real cap via plain
    /// assignment (the null placeholder drops harmlessly) before use. Use
    /// this instead of `adopt_received(0)` for an empty bare field.
    pub const fn null() -> Self {
        Self {
            slot: 0,
            depth: 0,
            origin: SlotOrigin::Global,
        }
    }

    /// Adopt a capability just **received** into a slot the caller owns —
    /// the landed slot `capture_transferred_cap` returns from a server
    /// receive arena, or a cap an IPC `Call` delivered into a freshly
    /// allocated receive slot. Resolves the slot's invoke depth and adopts
    /// it as [`SlotOrigin::Global`] (the slot came from the global
    /// allocator, directly or via an arena's injected allocator), so drop
    /// deletes the cap and returns the slot to `slot_alloc`.
    ///
    /// Global-allocator slots only. A cap caught in a bootstrap-reserved
    /// scratch window (`FixedRecvWindow`) must first be moved into a global
    /// slot (e.g. [`alloc_slot`] + a `cnode` move) — adopting the scratch
    /// slot directly would `slot_free` a slot the allocator never handed
    /// out. And never retain the raw slot elsewhere once adopted: the
    /// `OwnedCap` is the sole owner, and a second deleter would double-free.
    ///
    /// # Safety
    /// - `slot` is a global-allocator slot into which a cap was just received,
    ///   owned exclusively by the caller; no other owner frees it afterward.
    /// - Not a bootstrap-reserved scratch window (`FixedRecvWindow`) — move the
    ///   cap into a global slot first (the index must be one `slot_alloc` handed
    ///   out, or drop would `slot_free` a slot the allocator never owned).
    pub unsafe fn adopt_received(slot: Cap) -> Self {
        Self {
            slot,
            depth: slot_invoke_depth(slot),
            origin: SlotOrigin::Global,
        }
    }

    /// Borrow as a [`CapRef`] for an invocation (does not consume).
    pub fn borrow(&self) -> CapRef {
        CapRef::at_depth(self.slot, self.depth)
    }

    /// Peek the raw slot address without consuming or releasing.
    pub fn as_raw(&self) -> Cap {
        self.slot
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Take the raw slot, suppressing teardown. The caller becomes
    /// responsible for releasing the cap.
    #[must_use = "into_raw yields the raw slot and suppresses teardown; dropping it leaks the cap and its slot"]
    pub fn into_raw(self) -> Cap {
        let slot = self.slot;
        core::mem::forget(self);
        slot
    }

    /// Duplicate into a fresh slot (`cnode_copy`), keeping `self` live.
    /// Returns `None` on allocator / copy failure.
    pub fn duplicate(&self) -> Option<OwnedCap> {
        let temp = slot_alloc()?;
        let dst_depth = slot_invoke_depth(temp);
        if invoke::cnode_copy_ref(
            CAP_SELF_CSPACE,
            self.borrow(),
            CAP_SELF_CSPACE,
            CapRef::at_depth(temp, dst_depth),
            uapi::KERNITE_RIGHT_ALL as u64,
        ) != 0
        {
            slot_free(temp);
            return None;
        }
        Some(OwnedCap {
            slot: temp,
            depth: dst_depth,
            origin: SlotOrigin::Global,
        })
    }

    /// Consume this cap for an outbound IPC transfer: the kernel moves it
    /// out of our CSpace on send, and the resulting [`TransferCap`]
    /// reclaims the now-empty slot afterward.
    pub fn into_transfer(self) -> TransferCap {
        // Carry the depth into the TransferCap, then suppress this owner's
        // teardown (the TransferCap is now the sole owner of the slot).
        let cap = CapRef::at_depth(self.slot, self.depth);
        core::mem::forget(self);
        TransferCap {
            cap,
            owns_slot: true,
        }
    }

    /// Put a disposable copy on the wire while keeping `self`. Returns
    /// `None` on allocator / copy failure.
    pub fn duplicate_for_transfer(&self) -> Option<TransferCap> {
        dup_for_transfer(self.borrow())
    }
}

impl Drop for OwnedCap {
    fn drop(&mut self) {
        if self.slot != 0 {
            // SAFETY: an OwnedCap is the sole owner of `self.slot` at
            // `self.depth` (enforced by the unsafe adopters / safe constructors
            // that build it); this drop is its single teardown. `Global` returns
            // the index to the allocator; `Pool` leaves it to the SlotPool.
            match self.origin {
                SlotOrigin::Global => unsafe { delete_and_free_depth(self.slot, self.depth) },
                SlotOrigin::Pool => unsafe { delete_depth(self.slot, self.depth) },
            }
        }
    }
}

impl core::fmt::Debug for OwnedCap {
    /// Identity only — prints the slot address and depth without invoking
    /// the cap. Lets containing structs `#[derive(Debug)]`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedCap")
            .field("slot", &self.slot)
            .field("depth", &self.depth)
            .finish()
    }
}

/// A reference to a capability slot in *another* process's CSpace — the
/// child-layout slots a spawner installs caps into. The owner is the
/// child, not us, so a `ForeignSlot` has no drop behaviour; operations
/// that target it carry the child's CSpace cap explicitly.
#[derive(Clone, Copy)]
pub struct ForeignSlot {
    cspace: Cap,
    slot: Cap,
    depth: u8,
}

impl ForeignSlot {
    pub const fn new(cspace: Cap, slot: Cap, depth: u8) -> Self {
        Self {
            cspace,
            slot,
            depth,
        }
    }

    pub const fn cspace(&self) -> Cap {
        self.cspace
    }

    pub const fn slot(&self) -> Cap {
        self.slot
    }

    pub const fn depth(&self) -> u8 {
        self.depth
    }
}

// ===========================================================================
// OwnedMpPair — aggregate owner of an rsrcsrv MessagePipe pair.
// ===========================================================================

/// Single owner of an rsrcsrv-minted MessagePipe pair: the two side caps
/// plus the one `record_id` rsrcsrv assigned to the pair group.
/// [`alloc_mp_pair_owned`] mints all three together.
///
/// One record covers **both** side caps, so the pair must have exactly one
/// owner: copying the `record_id` into a second owner would free the
/// rsrcsrv record twice (and revoke the surviving peer early). This type is
/// that owner — move-only, holding each side as an `Option<OwnedCap>` so a
/// side handed to a peer becomes `None` and is never torn down locally
/// twice.
///
/// # Lifecycle
///
/// The pair owner is the group's lifecycle authority. The common path
/// keeps one side and hands the other to a peer over IPC with
/// [`take_send`](Self::take_send) / [`take_recv`](Self::take_recv) (which
/// move that side out as a [`TransferCap`], leaving it `None`).
/// [`release`](Self::release) is the teardown: it tears down whatever sides
/// remain locally, then frees the single rsrcsrv record exactly once —
/// which also revokes any side cap still held by a peer, reclaiming the
/// whole group.
///
/// # Why `release` and not `Drop`
///
/// Freeing the record issues rsrcsrv IPC ([`free_record`]); `Drop` can run
/// under a lock or during unwind, where IPC is unsafe, so `Drop` **never**
/// frees the record. A dropped `OwnedMpPair` still tears down its local
/// side caps (the `Option<OwnedCap>` fields drop normally); a debug build
/// additionally traps if the record was never released, to surface the
/// leak in tests. A handle embedded in slab / arena storage must therefore
/// have [`release_in_place`](Self::release_in_place) called (through the
/// `&mut` that slab access yields) on the server's explicit teardown path
/// before its slot is freed — `slot_free`'s `drop_in_place` runs `Drop`,
/// which cannot reclaim the record.
#[must_use = "an OwnedMpPair owns two side caps and an rsrcsrv record; release() it explicitly"]
pub struct OwnedMpPair {
    send: Option<OwnedCap>,
    recv: Option<OwnedCap>,
    record_id: u64,
}

impl OwnedMpPair {
    /// Adopt a `(send, recv, record_id)` triple minted by
    /// [`alloc_mp_pair_recorded`] (or received over IPC). Both slots come
    /// from the global allocator, so each side drops as
    /// [`SlotOrigin::Global`].
    ///
    /// # Safety
    /// - `send` and `recv` are distinct global-allocator slots, each holding one
    ///   side cap of the pair, owned exclusively by the returned aggregate.
    /// - `record_id` governs this pair group and is owned by no other
    ///   `OwnedMpPair` / `OwnedRecordedCap` (freed once at `release`).
    pub unsafe fn from_recorded(send: Cap, recv: Cap, record_id: u64) -> Self {
        Self {
            // SAFETY: caller guarantees `send`/`recv` are distinct global slots,
            // each holding a side cap and owned solely by this aggregate.
            send: Some(unsafe { OwnedCap::from_raw(send, slot_invoke_depth(send)) }),
            recv: Some(unsafe { OwnedCap::from_raw(recv, slot_invoke_depth(recv)) }),
            record_id,
        }
    }

    /// Borrow the send side for an invocation, or `None` once it has been
    /// handed out.
    pub fn send(&self) -> Option<CapRef> {
        self.send.as_ref().map(OwnedCap::borrow)
    }

    /// Borrow the recv side for an invocation, or `None` once it has been
    /// handed out.
    pub fn recv(&self) -> Option<CapRef> {
        self.recv.as_ref().map(OwnedCap::borrow)
    }

    /// The rsrcsrv record id covering the pair group. For diagnostics;
    /// release the record with [`release`](Self::release), not by hand.
    pub fn record_id(&self) -> u64 {
        self.record_id
    }

    /// Move the send side out for an outbound IPC transfer, leaving it
    /// `None`. The record stays with the pair (freed at
    /// [`release`](Self::release)). Returns `None` if the send side was
    /// already handed out.
    pub fn take_send(&mut self) -> Option<TransferCap> {
        self.send.take().map(OwnedCap::into_transfer)
    }

    /// Move the recv side out for an outbound IPC transfer, leaving it
    /// `None`. Mirror of [`take_send`](Self::take_send).
    pub fn take_recv(&mut self) -> Option<TransferCap> {
        self.recv.take().map(OwnedCap::into_transfer)
    }

    /// Teardown through a mutable borrow — for a pair embedded in a slab /
    /// arena struct reached by `&mut` (e.g. `TrackedSlab::slot_get_mut`),
    /// where the by-value [`release`](Self::release) cannot move `self` out.
    /// Releases any locally-held side caps, then frees the single rsrcsrv
    /// record (which also revokes any side still held by a peer, reclaiming
    /// the whole group). Local caps are torn down first so the reclaim never
    /// depends on the rsrcsrv revoke for our own slots. The Drop leak-trap
    /// is disarmed (`record_id` zeroed, sides `None`) only when `free_record`
    /// succeeds, so a later `Drop` of the emptied `self` is a no-op; on
    /// failure `record_id` stays set — the `Err` is returned for the caller
    /// to handle, and the eventual `Drop` still surfaces the leak.
    pub fn release_in_place(&mut self) -> Result<(), u64> {
        // Local side caps first: each `OwnedCap::drop` deletes the cap and
        // frees its slot. A side already handed out is `None` — no-op.
        drop(self.send.take());
        drop(self.recv.take());
        let result = free_record(self.record_id);
        if result.is_ok() {
            self.record_id = 0;
        }
        result
    }

    /// Teardown of an owned-by-value pair — delegates to
    /// [`release_in_place`](Self::release_in_place) and drops the emptied
    /// `self`. Use this when you own the pair by value; use
    /// `release_in_place` for a pair stored in a slab / arena struct reached
    /// by `&mut`. On a `free_record` failure the dropped `self` trips the
    /// debug leak-trap, so prefer `release_in_place` when you must handle the
    /// `Err`.
    pub fn release(mut self) -> Result<(), u64> {
        self.release_in_place()
    }
}

impl Drop for OwnedMpPair {
    fn drop(&mut self) {
        // The `Option<OwnedCap>` fields drop after this body, tearing down
        // any locally-held side caps. The rsrcsrv record is NOT freed here
        // (free_record issues IPC, unsafe under locks / unwind) — that is
        // the job of release() / release_in_place(). A non-zero record_id
        // means neither ran (or its free_record failed): trap in debug to
        // surface the leak; release builds drop quietly (local caps still
        // tear down).
        debug_assert!(
            self.record_id == 0,
            "OwnedMpPair dropped without release(): rsrcsrv record leaked"
        );
    }
}

// ===========================================================================
// OwnedRecordedCap — aggregate owner of a single rsrcsrv-recorded object.
// ===========================================================================

/// Single owner of an rsrcsrv-minted object: the cap plus the `record_id`
/// rsrcsrv assigned to it. [`alloc_object_owned`] mints both together.
///
/// The single-cap analogue of [`OwnedMpPair`]. There is no shared-record
/// hazard here (one record, one cap), but binding the cap and its record
/// into one owner is still what makes teardown correct by construction: the
/// record is the part that, left as a loose `u64`, gets forgotten across a
/// server's error / teardown branches and accumulates under the owner id in
/// rsrcsrv's table. [`release`](Self::release) frees both in one call.
///
/// The cap is held as an `Option<OwnedCap>` so it can be handed to a peer
/// over IPC ([`take_for_transfer`](Self::take_for_transfer), which moves it
/// out and leaves `None`) while this owner keeps the record and frees it at
/// [`release`](Self::release).
///
/// # Why `release` and not `Drop`
///
/// As with [`OwnedMpPair`], freeing the record issues rsrcsrv IPC
/// ([`free_record`]) and must not run from `Drop`. `Drop` tears down only
/// the local cap; a non-zero `record_id` at drop means `release` was never
/// called (or its `free_record` failed), which a debug build traps to
/// surface the leak.
#[must_use = "an OwnedRecordedCap owns a cap and an rsrcsrv record; release() it explicitly"]
pub struct OwnedRecordedCap {
    cap: Option<OwnedCap>,
    record_id: u64,
}

impl OwnedRecordedCap {
    /// Adopt a `(slot, record_id)` pair minted by [`alloc_object_recorded`]
    /// (or received over IPC). The slot comes from the global allocator, so
    /// the cap drops as [`SlotOrigin::Global`].
    ///
    /// # Safety
    /// - `slot` is a global-allocator slot holding the object cap, owned
    ///   exclusively by the returned aggregate.
    /// - `record_id` governs this object and is owned by no other aggregate
    ///   (freed once at `release`).
    pub unsafe fn from_recorded(slot: Cap, record_id: u64) -> Self {
        Self {
            // SAFETY: caller guarantees `slot` is a global slot holding the cap,
            // owned solely by this aggregate.
            cap: Some(unsafe { OwnedCap::from_raw(slot, slot_invoke_depth(slot)) }),
            record_id,
        }
    }

    /// Wrap an existing [`OwnedCap`] together with the rsrcsrv `record_id`
    /// that governs it.
    ///
    /// The cap is a proven `OwnedCap` moved in, so there is no memory-safety
    /// obligation here. The `record_id`, however, must be owned **exclusively**
    /// by the returned aggregate: a `record_id` already governed by another
    /// `OwnedRecordedCap` / `OwnedMpPair` would be freed twice at `release`,
    /// double-freeing the rsrcsrv record (and revoking a peer's object early).
    pub fn from_owned(cap: OwnedCap, record_id: u64) -> Self {
        Self {
            cap: Some(cap),
            record_id,
        }
    }

    /// Borrow the cap for an invocation, or `None` once it has been handed
    /// out.
    pub fn borrow(&self) -> Option<CapRef> {
        self.cap.as_ref().map(OwnedCap::borrow)
    }

    /// Peek the raw cap slot without consuming, or `None` once handed out.
    pub fn as_raw(&self) -> Option<Cap> {
        self.cap.as_ref().map(OwnedCap::as_raw)
    }

    /// The rsrcsrv record id governing this object. For diagnostics;
    /// release it with [`release`](Self::release), not by hand.
    pub fn record_id(&self) -> u64 {
        self.record_id
    }

    /// Move the cap out for an outbound IPC transfer, leaving it `None`.
    /// The record stays with this owner (freed at
    /// [`release`](Self::release)). Returns `None` if already handed out.
    pub fn take_for_transfer(&mut self) -> Option<TransferCap> {
        self.cap.take().map(OwnedCap::into_transfer)
    }

    /// Teardown through a mutable borrow — for an aggregate embedded in a
    /// slab / arena struct reached by `&mut` (e.g. `TrackedSlab::slot_get_mut`),
    /// where the by-value [`release`](Self::release) cannot move `self` out.
    /// Releases the locally-held cap (if any), then frees the rsrcsrv record.
    /// The Drop leak-trap is disarmed (`record_id` zeroed, cap `None`) only
    /// when `free_record` succeeds, so a later `Drop` of the emptied `self`
    /// is a no-op; on failure `record_id` stays set — the `Err` is returned
    /// for the caller to handle, and the eventual `Drop` still surfaces the
    /// leak.
    pub fn release_in_place(&mut self) -> Result<(), u64> {
        drop(self.cap.take());
        let result = free_record(self.record_id);
        if result.is_ok() {
            self.record_id = 0;
        }
        result
    }

    /// Teardown of an owned-by-value aggregate — delegates to
    /// [`release_in_place`](Self::release_in_place) and drops the emptied
    /// `self`. Use `release_in_place` for an aggregate stored in a slab /
    /// arena struct reached by `&mut`. On a `free_record` failure the dropped
    /// `self` trips the debug leak-trap, so prefer `release_in_place` when you
    /// must handle the `Err`.
    pub fn release(mut self) -> Result<(), u64> {
        self.release_in_place()
    }
}

impl Drop for OwnedRecordedCap {
    fn drop(&mut self) {
        // The `Option<OwnedCap>` field drops after this body, tearing down
        // the local cap. The rsrcsrv record is freed only by release() /
        // release_in_place() (free_record issues IPC, unsafe under locks /
        // unwind). A non-zero record_id means neither ran (or its
        // free_record failed): trap in debug to surface the leak.
        debug_assert!(
            self.record_id == 0,
            "OwnedRecordedCap dropped without release(): rsrcsrv record leaked"
        );
    }
}

/// Allocate a CNode slot as an [`OwnedSlot`] — the owned-API counterpart
/// to [`slot_alloc`]. The slot is returned to the allocator on drop until
/// a cap is installed and [`OwnedSlot::assume_filled`] is called.
pub fn alloc_slot() -> Option<OwnedSlot> {
    let slot = slot_alloc()?;
    Some(OwnedSlot {
        slot,
        depth: slot_invoke_depth(slot),
    })
}

/// Owned-API counterpart to [`slot_alloc_no_expand`]: allocate a slot as an
/// [`OwnedSlot`] from already-registered segments only, never triggering CSpace
/// self-expansion. For allocators that must not recurse into expansion (e.g.
/// rsrcsrv's carve-out handler, which already holds the allocator lock).
pub fn alloc_slot_no_expand() -> Option<OwnedSlot> {
    let slot = slot_alloc_no_expand()?;
    Some(OwnedSlot {
        slot,
        depth: slot_invoke_depth(slot),
    })
}

/// Owned-API counterpart to [`slot_alloc_or_idle`]: allocate a slot as an
/// [`OwnedSlot`]. Like its raw counterpart this never returns on pool
/// exhaustion — the failure is unrecoverable and halts the calling thread
/// with a diagnostic naming `context`.
pub fn alloc_slot_or_idle(context: &[u8]) -> OwnedSlot {
    let slot = slot_alloc_or_idle(context);
    OwnedSlot {
        slot,
        depth: slot_invoke_depth(slot),
    }
}

/// Owned-API counterpart to [`alloc_object_recorded`]: the freshly retyped
/// object is returned as an [`OwnedRecordedCap`] binding the cap and its
/// rsrcsrv `record_id` into one owner, released together via
/// [`OwnedRecordedCap::release`]. The raw [`alloc_object_recorded`] remains
/// the low-level escape hatch.
pub fn alloc_object_owned(obj_type: u64, size_bits: u64) -> Result<OwnedRecordedCap, u64> {
    let (slot, record_id) = alloc_object_recorded(obj_type, size_bits)?;
    // SAFETY: alloc_object_recorded just minted `slot` (a fresh global-allocator
    // slot holding the object cap) and `record_id`, both owned solely by this
    // new aggregate.
    Ok(unsafe { OwnedRecordedCap::from_recorded(slot, record_id) })
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

unsafe fn slot_mark_used_locked(slot: Cap) -> bool {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized {
            return false;
        }
        for idx in 0..state.seg_count {
            let seg = &mut state.segments[idx];
            if let Some(slot_idx) = segment_slot_index(seg, slot) {
                if segment_is_used(seg, slot_idx) {
                    return false;
                }
                segment_mark_used(seg, slot_idx);
                if slot_idx < seg.alloc_hint as usize {
                    seg.alloc_hint = slot_idx as u64;
                }
                return true;
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
// Self-expansion protocol helpers
// ===========================================================================

/// In-process self-expansion: install one new sub-CNode in the deterministic
/// expansion window. Caller holds SLOT_LOCK.
///
/// Procedure:
///   1. Arm the IPC receive window at `expand_temp_slot`, then call
///      RSRC_ALLOC(rsrcsrv, OBJ_CNODE, SLOT_EXPAND_BITS_DEFAULT, flags=0).
///   2. cnode_set_guard(temp, 0, 0) — sub-CNodes have no guard.
///   3. cnode_move(SELF, expand_base + count, SELF, temp) — graft into the
///      root expansion window. `cnode_move` empties `temp`, leaving the
///      reserved slot reusable for the next call.
///   4. Register the new segment with the allocator.
///
/// rsrcsrv overrides this in-process path by installing its own carve-out
/// via [`install_expand_handler`] (it would deadlock retyping its own
/// allocation handle table over IPC to itself).
unsafe fn self_expand_locked(state: &mut SlotAllocState) -> ExpandProgress {
    unsafe {
        // Reaching the configured per-process expansion ceiling is a normal
        // limit, not an invariant violation — let callers decide what to do.
        if state.cspace_expand_count >= max_expansions_locked(state) {
            return ExpandProgress::Failed;
        }
        if let Some(handler) = state.expand_handler {
            let Some(plan) = external_expand_plan_locked(state) else {
                return ExpandProgress::Failed;
            };
            return handler(plan);
        }
        if state.runtime_authority_ep == 0 {
            fatal_self_expand(b"runtime_authority_ep == 0 with no carve-out handler");
        }
        if state.expand_temp_slot == 0 {
            fatal_self_expand(b"expand_temp_slot == 0 (reserve_expand_temp_slot not called)");
        }

        let temp = state.expand_temp_slot;
        let dest_root_slot = state.expand_base + state.cspace_expand_count as u64;

        let ctx = crate::current_ipc_ctx();
        if ctx.is_null() {
            fatal_self_expand(b"current_ipc_ctx() returned null");
        }

        crate::core::ipc_ext::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE.addr(), temp, 0);

        // RSRC_ALLOC wire layout: regs[0]=obj_type, regs[1]=size_bits,
        // regs[2]=flags. The receive destination is carried through the
        // IPC buffer's receive-window fields, not through the payload.
        // `owner_id` is no longer wire-visible — rsrcsrv identifies the
        // owner from the badge of the per-client MP record.
        let mut req = trona_kernel::core_types::TronaMsg::zeroed();
        req.label = RSRC_ALLOC;
        req.length = 3;
        req.regs[0] = OBJ_CNODE;
        req.regs[1] = SLOT_EXPAND_BITS_DEFAULT;
        req.regs[2] = 0;
        let mut resp = trona_kernel::core_types::TronaMsg::zeroed();
        let err = trona_kernel::ipc::mp_call_ctx(
            ctx,
            state.runtime_authority_ep,
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || resp.label != TRONA_OK {
            fatal_self_expand(b"RSRC_ALLOC(OBJ_CNODE) failed");
        }

        if invoke::cnode_set_guard(CapRef::flat(temp), 0, 0) != 0 {
            fatal_self_expand(b"cnode_set_guard on expansion sub-CNode failed");
        }

        if invoke::cnode_move(CAP_SELF_CSPACE, dest_root_slot, CAP_SELF_CSPACE, temp) != 0 {
            fatal_self_expand(b"cnode_move into expansion window failed");
        }

        let packed_base = dest_root_slot << SLOT_EXPAND_BITS_DEFAULT;
        let count = 1u64 << SLOT_EXPAND_BITS_DEFAULT;

        // MAX_SEGMENTS sized for MAX_CSPACE_EXPANSIONS + layout headroom; if
        // we hit it before max_expansions_locked, the budgets are skewed.
        if state.seg_count >= MAX_SEGMENTS {
            fatal_self_expand(b"segment table full before MAX_CSPACE_EXPANSIONS");
        }
        let si = state.seg_count;
        state.segments[si] = Segment {
            base: packed_base,
            count,
            alloc_hint: 0,
            used: 0,
            bits: [0; SEGMENT_BITMAP_WORDS],
        };
        state.seg_count += 1;
        state.active_seg = si;
        state.cspace_expand_count += 1;

        if state.root_bits > 0 {
            state.expanded_depth = state.root_bits + SLOT_EXPAND_BITS_DEFAULT as u8;
        }

        crate::udebug!(|_lb| {
            _lb.str(b"[SLOT] cspace-expand: install base=");
            _lb.hex(packed_base);
            _lb.str(b" count=");
            _lb.hex(count);
            _lb.str(b" (seg ");
            _lb.hex(si as u64);
            _lb.str(b")\n");
        });

        ExpandProgress::Completed
    }
}

/// Allocate a single CSpace slot, or halt the thread on exhaustion.
///
/// This is the correct call for a server's `init_private_slots` path:
/// slot-pool exhaustion there is unrecoverable because the service
/// cannot register its own receive slot or private notification, and
/// returning a sentinel such as `0` would silently land on
/// `CAP_SELF_TCB` (slot 0 in every child) and corrupt the thread on
/// the first received capability.
///
/// `context` is a short byte string naming the caller — the
/// service and slot description — that is emitted in the fatal log so
/// the diagnostic identifies which site halted.
pub fn slot_alloc_or_idle(context: &[u8]) -> Cap {
    match slot_alloc() {
        Some(s) => s,
        None => fatal_slot_alloc(context, 1),
    }
}

/// Consecutive-range variant of [`slot_alloc_or_idle`]. Halts when the
/// pool cannot satisfy a run of `count` slots.
pub fn slot_alloc_consecutive_or_idle(count: u64, context: &[u8]) -> Cap {
    match slot_alloc_consecutive(count) {
        Some(s) => s,
        None => fatal_slot_alloc(context, count),
    }
}

fn fatal_slot_alloc(context: &[u8], requested: u64) -> ! {
    let (remaining, auth, has_handler, expansions, base, limit) = expansion_state();
    crate::uerror!(|_lb| {
        _lb.str(b"[slot_alloc] FATAL: exhausted for ");
        _lb.str(context);
        _lb.str(b" requested=");
        _lb.dec(requested);
        _lb.str(b" remaining=");
        _lb.dec(remaining);
        _lb.str(b" expansions=");
        _lb.dec(expansions as u64);
        _lb.str(b" expand_window=[");
        _lb.hex(base);
        _lb.str(b",");
        _lb.hex(limit);
        _lb.str(b") auth_set=");
        _lb.dec(if auth { 1 } else { 0 });
        _lb.str(b" handler=");
        _lb.dec(if has_handler { 1 } else { 0 });
        _lb.str(b"\n");
    });
    // Power-of-two yield cadence: 1, 2, 4, 8, 16, ..., so the first
    // minute of hangs logs ~12 lines and every subsequent doubling
    // (≈1 minute doubling at idle) keeps the long-hang log readable.
    let mut tick: u64 = 0;
    loop {
        trona_kernel::syscall::yield_now();
        tick = tick.wrapping_add(1);
        if tick & (tick.wrapping_sub(1)) == 0 {
            crate::uerror!(|_lb| {
                _lb.str(b"[slot_alloc] FATAL: still exhausted for ");
                _lb.str(context);
                _lb.str(b" (yield #");
                _lb.dec(tick);
                _lb.str(b")\n");
            });
        }
    }
}

/// Halt on self-expansion invariant violation. Reaching the configured
/// `MAX_CSPACE_EXPANSIONS` ceiling is *not* a violation and stays an
/// `ExpandProgress::Failed` return; this helper is for genuinely broken
/// state — missing authority/temp slot, kernel invocation rejection, or a
/// segment-table budget skew that should have been caught at boot.
fn fatal_self_expand(reason: &[u8]) -> ! {
    crate::uerror!(|_lb| {
        _lb.str(b"[slot_alloc] FATAL self_expand: ");
        _lb.str(reason);
        _lb.str(b"\n");
    });
    loop {
        trona_kernel::syscall::yield_now();
    }
}

// ===========================================================================
// Self-expansion configuration
// ===========================================================================

/// Enable self-expansion. Called once during init's runtime-phase transition
/// (or rsrcsrv's bootstrap epilogue) once the rsrcsrv authority endpoint is
/// available. Subsequent allocator exhaustion drives [`self_expand`] until
/// `MAX_CSPACE_EXPANSIONS` sub-CNodes are installed.
///
/// # Safety
/// Must be called from a single-threaded init/CRT phase before concurrent
/// `slot_alloc` traffic begins.
pub unsafe fn enable_self_expand(authority_ep: Cap, owner_id: u64) {
    unsafe {
        slot_lock_acquire();
        let state = &mut *(&raw mut SLOT_ALLOC);
        state.runtime_authority_ep = authority_ep;
        state.runtime_owner_id = owner_id;
        if state.expand_base == 0 && state.expand_limit == 0 {
            state.expand_base = CSPACE_EXPAND_BASE;
            state.expand_limit = CSPACE_EXPAND_BASE + MAX_CSPACE_EXPANSIONS as u64;
        }
        if state.root_bits == 0 {
            let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
            if info.error == 0 {
                let ctx = crate::current_ipc_ctx();
                if !ctx.is_null() && !(*ctx).ipc_buffer.is_null() {
                    state.root_bits = (*(*ctx).ipc_buffer).msg[2] as u8;
                }
            }
        }
        slot_lock_release();
    }
}

/// Allocate a CSpace slot and retype a kernel object into it via the
/// process's authority server (rsrcsrv). On `TRONA_OK` the slot holds
/// a freshly retyped cap of `obj_type`; on failure the slot is
/// released and the wire reply label (or IPC error) is returned.
///
/// `obj_type` is one of `KERNITE_OBJ_*`; `size_bits` is the kernel's
/// per-type sizing argument — frame log2 size for `OBJ_FRAME`, depth
/// log2 for `OBJ_EVENT_QUEUE`, ignored for fixed-size objects (Timer,
/// Watch).
///
/// Used by substrate-side lazy resource paths (POSIX nanosleep's
/// Timer + EventQueue pair, fault-pipe materialisation) that need
/// kernel objects without going through the `RSRC_ALLOC` wire
/// boilerplate.
pub fn alloc_object_recorded(obj_type: u64, size_bits: u64) -> Result<(Cap, u64), u64> {
    let slot = match slot_alloc() {
        Some(s) => s,
        None => return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as u64),
    };

    slot_lock_acquire();
    let (mut authority_ep, owner_id) = unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        (state.runtime_authority_ep, state.runtime_owner_id)
    };
    slot_lock_release();

    // Lazy bind to rsrcsrv on first use. Prefer the eager weak symbol
    // populated by rtld from `ROLE_RSRCSRV_CLIENT`; only fall back to
    // `caps::rsrcsrv_ep()` (which issues `NAMESRV_LOOKUP`) when the
    // allocator has free slots, so the lookup's own slot needs can be
    // met. rsrcsrv itself never reaches this lazy path because it
    // overwrites the expand handler with its own carve-out before its
    // first allocation.
    if authority_ep == 0 {
        // SAFETY: weak symbol init-by-rtld contract (see weak.rs).
        let cached =
            unsafe { ::core::ptr::read_volatile(&raw const crate::__trona_cap_rsrcsrv_ep) };
        let resolved = if cached != 0 {
            cached
        } else if slot_alloc_remaining() > 0 {
            crate::client::caps::rsrcsrv_ep().addr()
        } else {
            0
        };
        if resolved == 0 {
            slot_free(slot);
            return Err(uapi::KERNITE_ERR_INVALID_OPERATION as u64);
        }
        unsafe {
            slot_lock_acquire();
            let state = &mut *(&raw mut SLOT_ALLOC);
            // Another thread may have raced ahead with the same lookup;
            // either result is a sibling cap referring to the same MP,
            // so the first writer wins and `caps::rsrcsrv_ep` cached
            // both. Use whichever the state currently holds.
            if state.runtime_authority_ep == 0 {
                state.runtime_authority_ep = resolved;
            }
            authority_ep = state.runtime_authority_ep;
            slot_lock_release();
        }
    }

    let ctx = crate::current_ipc_ctx();
    if ctx.is_null() {
        slot_free(slot);
        return Err(uapi::KERNITE_ERR_INVALID_OPERATION as u64);
    }

    let _ = owner_id; // owner identity now comes from the per-client MP badge

    let record_id;
    unsafe {
        crate::core::ipc_ext::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE.addr(), slot, 0);

        let mut req = trona_kernel::core_types::TronaMsg::zeroed();
        req.label = RSRC_ALLOC;
        req.length = 3;
        req.regs[0] = obj_type;
        req.regs[1] = size_bits;
        req.regs[2] = 0;
        let mut resp = trona_kernel::core_types::TronaMsg::zeroed();
        let err = trona_kernel::ipc::mp_call_ctx(
            ctx,
            authority_ep,
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            slot_free(slot);
            return Err(err as u64);
        }
        if resp.label != TRONA_OK {
            slot_free(slot);
            return Err(resp.label);
        }
        record_id = resp.regs[0];
    }

    Ok((slot, record_id))
}

/// Thin wrapper over [`alloc_object_recorded`] for callers that only
/// need the cap and rely on `RSRC_OWNER_EXITED` for reclaim (genuine
/// process-lifetime objects). Per-client / per-session objects must
/// use [`alloc_object_recorded`] and release the record id with
/// [`free_record`] at teardown.
pub fn alloc_object(obj_type: u64, size_bits: u64) -> Result<Cap, u64> {
    alloc_object_recorded(obj_type, size_bits).map(|(slot, _)| slot)
}

/// Allocate a fresh MessagePipe pair via the process's authority
/// server (rsrcsrv's `LABEL_ALLOC_MP_PAIR`). On `TRONA_OK` the
/// caller's CSpace holds two newly-installed sides at
/// `(send_slot, recv_slot)`, where `recv_slot == send_slot + 1`.
/// The matching `MessagePipeCore` is back-referenced by rsrcsrv so
/// the caller never sees the core; closing both sides releases
/// the entire pair through `RSRC_OWNER_EXITED`.
///
/// Both sides are bidirectional at the kernel ABI level
/// (`MP_WRITE` and `MP_READ` work on either). The returned
/// labelling reflects vfs convention — typical use puts the
/// "send" side on the producer (the request-issuing party) and
/// the "recv" side on the consumer (the dispatcher receiving the
/// callback).
///
/// Returns `Err(label)` on slot-allocator exhaustion, IPC
/// failure, or rsrcsrv reporting quota / OOM.
pub fn alloc_mp_pair_recorded() -> Result<(Cap, Cap, u64), u64> {
    let send_slot = match slot_alloc_consecutive(2) {
        Some(b) => b,
        None => return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as u64),
    };
    let recv_slot = send_slot + 1;

    slot_lock_acquire();
    let mut authority_ep = unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        state.runtime_authority_ep
    };
    slot_lock_release();
    if authority_ep == 0 {
        // SAFETY: weak symbol init-by-rtld contract (see weak.rs).
        let cached =
            unsafe { ::core::ptr::read_volatile(&raw const crate::__trona_cap_rsrcsrv_ep) };
        let resolved = if cached != 0 {
            cached
        } else if slot_alloc_remaining() > 0 {
            crate::client::caps::rsrcsrv_ep().addr()
        } else {
            0
        };
        if resolved == 0 {
            slot_free_consecutive(send_slot, 2);
            return Err(uapi::KERNITE_ERR_INVALID_OPERATION as u64);
        }
        unsafe {
            slot_lock_acquire();
            let state = &mut *(&raw mut SLOT_ALLOC);
            if state.runtime_authority_ep == 0 {
                state.runtime_authority_ep = resolved;
            }
            authority_ep = state.runtime_authority_ep;
            slot_lock_release();
        }
    }

    let ctx = crate::current_ipc_ctx();
    if ctx.is_null() {
        slot_free_consecutive(send_slot, 2);
        return Err(uapi::KERNITE_ERR_INVALID_OPERATION as u64);
    }

    // rsrcsrv `handle_alloc_mp_pair` mints the two sides directly
    // into caller's CSpace at receive_index / receive_index+1, so
    // arm `send_slot` as the base of the receive range before the
    // mp_call.
    unsafe {
        crate::core::ipc_ext::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE.addr(), send_slot, 0);
    }

    let mut req = trona_kernel::core_types::TronaMsg::zeroed();
    req.label = LABEL_ALLOC_MP_PAIR;
    req.length = 0;
    let mut resp = trona_kernel::core_types::TronaMsg::zeroed();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            authority_ep,
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        slot_free_consecutive(send_slot, 2);
        return Err(err as u64);
    }
    if resp.label != TRONA_OK {
        slot_free_consecutive(send_slot, 2);
        return Err(resp.label);
    }
    Ok((send_slot, recv_slot, resp.regs[0]))
}

/// Thin wrapper over [`alloc_mp_pair_recorded`] for callers that only
/// need the two side caps and rely on `RSRC_OWNER_EXITED` for reclaim.
/// Per-client / per-session pairs must use [`alloc_mp_pair_recorded`]
/// and release the core record id with [`free_record`] at teardown
/// (which frees the whole pair group).
pub fn alloc_mp_pair() -> Result<(Cap, Cap), u64> {
    alloc_mp_pair_recorded().map(|(send, recv, _)| (send, recv))
}

/// Allocate an rsrcsrv MessagePipe pair as a single [`OwnedMpPair`] — the
/// owned-API counterpart to [`alloc_mp_pair_recorded`]. Use this for
/// per-client / per-session pairs whose record must be released at
/// teardown: the returned owner ties both side caps and the record into
/// one [`OwnedMpPair::release`] call. (Process-lifetime pairs that rely on
/// `RSRC_OWNER_EXITED` for reclaim can still use the lighter
/// [`alloc_mp_pair`].)
pub fn alloc_mp_pair_owned() -> Result<OwnedMpPair, u64> {
    let (send, recv, record_id) = alloc_mp_pair_recorded()?;
    // SAFETY: alloc_mp_pair_recorded just minted `send`/`recv` (distinct fresh
    // global-allocator slots, one side cap each) and `record_id`, all owned
    // solely by this new aggregate.
    Ok(unsafe { OwnedMpPair::from_recorded(send, recv, record_id) })
}

/// Release an rsrcsrv object record by id via `RSRC_FREE`, vacating
/// its ObjectTable slot and revoking rsrcsrv's back-ref (which also
/// revokes any surviving cap copies). For an MP/DP pair, pass the
/// core record id — rsrcsrv frees the whole pair group. The caller's
/// own cap slots are released separately (e.g. via
/// [`delete_and_free`]); this only reclaims the rsrcsrv-side
/// record so long-lived servers do not accumulate per-client records
/// under their owner id. `record_id == 0` is a no-op.
pub fn free_record(record_id: u64) -> Result<(), u64> {
    if record_id == 0 {
        return Ok(());
    }

    slot_lock_acquire();
    let mut authority_ep = unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        state.runtime_authority_ep
    };
    slot_lock_release();
    if authority_ep == 0 {
        // SAFETY: `__trona_cap_rsrcsrv_ep` is initialised once by rtld
        // before any user code runs; a volatile load is the documented
        // getter. Reads the eager path populated by spawners under
        // ROLE_RSRCSRV_CLIENT — costs nothing.
        let cached =
            unsafe { ::core::ptr::read_volatile(&raw const crate::__trona_cap_rsrcsrv_ep) };
        if cached != 0 {
            unsafe {
                slot_lock_acquire();
                let state = &mut *(&raw mut SLOT_ALLOC);
                if state.runtime_authority_ep == 0 {
                    state.runtime_authority_ep = cached;
                }
                authority_ep = state.runtime_authority_ep;
                slot_lock_release();
            }
        } else {
            // No eager cap and no expansion authority: refuse the call.
            // The lazy `caps::rsrcsrv_ep()` fallback would issue
            // `NAMESRV_LOOKUP` and recurse into slot allocation — that
            // is exactly the deadlock-on-exhaustion path this avoids.
            return Err(uapi::KERNITE_ERR_INVALID_OPERATION as u64);
        }
    }

    let ctx = crate::current_ipc_ctx();
    if ctx.is_null() {
        return Err(uapi::KERNITE_ERR_INVALID_OPERATION as u64);
    }

    let mut req = trona_kernel::core_types::TronaMsg::zeroed();
    req.label = LABEL_FREE;
    req.length = 1;
    req.regs[0] = record_id;
    let mut resp = trona_kernel::core_types::TronaMsg::zeroed();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            authority_ep,
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(err as u64);
    }
    if resp.label != TRONA_OK {
        return Err(resp.label);
    }
    Ok(())
}

/// Free `count` consecutive slots starting at `base`. Each slot is
/// returned to the per-process slot allocator individually; the
/// allocator does not track consecutive runs explicitly so the
/// freed slots may be re-issued individually.
fn slot_free_consecutive(base: Cap, count: u64) {
    for offset in 0..count {
        slot_free(base + offset);
    }
}

/// rsrcsrv's `LABEL_ALLOC_MP_PAIR` — vended directly from
/// `userland/core/rsrcsrv/src/labels.rs`. Inlined here so substrate
/// users can drive MP pair allocation without a dependency on the
/// rsrcsrv crate.
const LABEL_ALLOC_MP_PAIR: u64 = 0x30A;

/// rsrcsrv `LABEL_FREE` — release one object record (or a whole
/// MP/DP pair group when given the core record id) owned by the
/// caller's badge.
const LABEL_FREE: u64 = 0x301;

/// Reserve the per-process slot used as the destination for `OBJ_CNODE`
/// retypes during self-expansion. The slot must come from a permanent,
/// non-allocator-managed range (e.g. init's bootstrap permanent pool) so
/// `self_expand` can reuse it without recursing into `slot_alloc`.
///
/// `cnode_move` empties the slot after each install, so a single reserved
/// slot suffices for all subsequent expansions.
///
/// # Safety
/// Must be called once before the first `self_expand` trigger.
pub unsafe fn reserve_expand_temp_slot(slot: Cap) {
    unsafe {
        slot_lock_acquire();
        let state = &mut *(&raw mut SLOT_ALLOC);
        state.expand_temp_slot = slot;
        slot_lock_release();
    }
}

/// Install a self-expansion handler. When set, [`self_expand_locked`]
/// dispatches through this callback instead of running its in-process retype
/// path. rsrcsrv installs a handler that retypes `OBJ_CNODE` directly from
/// its own untyped pool, sidestepping the `RSRC_ALLOC` IPC that would
/// otherwise re-enter rsrcsrv's own request loop.
///
/// # Safety
/// Handler runs with `SLOT_LOCK` held (from `self_expand_locked`'s caller);
/// it must not call `slot_alloc` or otherwise re-acquire `SLOT_LOCK`.
pub unsafe fn install_expand_handler(h: ExpandHandler) {
    unsafe {
        slot_lock_acquire();
        let state = &mut *(&raw mut SLOT_ALLOC);
        state.expand_handler = Some(h);
        slot_lock_release();
    }
}

unsafe fn register_external_segment_inner(
    state: &mut SlotAllocState,
    base: Cap,
    count: u64,
) -> bool {
    if state.seg_count >= MAX_SEGMENTS {
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
    state.cspace_expand_count += 1;
    if state.root_bits > 0 {
        state.expanded_depth = state.root_bits + SLOT_EXPAND_BITS_DEFAULT as u8;
    }
    true
}

fn external_expand_plan_locked(state: &SlotAllocState) -> Option<ExternalExpandPlan> {
    if !state.initialized
        || state.cspace_expand_count >= max_expansions_locked(state)
        || state.seg_count >= MAX_SEGMENTS
        || state.expand_limit <= state.expand_base
    {
        return None;
    }
    let root_slot = state.expand_base + state.cspace_expand_count as u64;
    Some(ExternalExpandPlan {
        root_slot,
        packed_base: root_slot << SLOT_EXPAND_BITS_DEFAULT,
        slot_count: 1u64 << SLOT_EXPAND_BITS_DEFAULT,
        cnode_size_bits: SLOT_EXPAND_BITS_DEFAULT,
    })
}

/// Commit a sub-CNode that an external handler has already installed.
///
/// # Safety
/// `SLOT_LOCK` must be held by the caller for the duration of this call.
pub unsafe fn commit_external_expand_locked(plan: ExternalExpandPlan) -> bool {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized
            || state.cspace_expand_count >= max_expansions_locked(state)
            || state.seg_count >= MAX_SEGMENTS
            || state.expand_limit <= state.expand_base
        {
            return false;
        }
        let expected_root = state.expand_base + state.cspace_expand_count as u64;
        if plan.root_slot != expected_root
            || plan.packed_base != (expected_root << SLOT_EXPAND_BITS_DEFAULT)
            || plan.slot_count != (1u64 << SLOT_EXPAND_BITS_DEFAULT)
            || plan.cnode_size_bits != SLOT_EXPAND_BITS_DEFAULT
        {
            return false;
        }
        register_external_segment_inner(state, plan.packed_base, plan.slot_count)
    }
}

/// Drive one self-expansion attempt. Used for eager pre-install during init's
/// runtime-phase transition (so the first user-driven fork does not have to
/// expand mid-flight) and for rsrcsrv's bootstrap epilogue.
pub fn self_expand() -> ExpandProgress {
    slot_lock_acquire();
    let progress = unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        self_expand_locked(state)
    };
    slot_lock_release();
    progress
}

// ===========================================================================
// trona_server::recv_slot::SlotAllocator adapter callbacks
// ===========================================================================

/// Adapter callback for `trona_server::recv_slot::SlotAllocator::alloc_consecutive`.
/// Wraps [`slot_alloc_consecutive`] in the `unsafe fn(u64) -> Option<u64>`
/// shape the server crate expects, so a server binary can compose a
/// `SlotAllocator` from runtime callbacks without `trona_runtime` having
/// to know about `trona_server`.
///
/// # Safety
///
/// Same contract as [`slot_alloc_consecutive`]: the per-process slot
/// allocator must be initialised (via `runtime_init_slot_allocator`)
/// before this is invoked. Returns `None` on exhaustion.
pub unsafe fn slot_alloc_consecutive_cb(count: u64) -> Option<Cap> {
    slot_alloc_consecutive(count)
}

/// Adapter callback for `trona_server::recv_slot::SlotAllocator::invoke_depth`.
/// Wraps [`slot_invoke_depth`] in the `unsafe fn(u64) -> u8` shape the
/// server crate expects.
///
/// # Safety
///
/// Same contract as [`slot_invoke_depth`]: safe to call concurrently
/// with other allocator queries; reads `SLOT_ALLOC` state under the
/// allocator's internal lock.
pub unsafe fn slot_invoke_depth_cb(slot: Cap) -> u8 {
    slot_invoke_depth(slot)
}

/// Allocate one kernel object of `obj_type` (kernel depth/size `size_bits`)
/// from this process's rsrcsrv authority, returning the owning [`OwnedCap`].
///
/// Server reactors call this at startup to self-provision the `EventQueue`
/// and `Watch` objects their `EventLoop` blocks on. It delegates to
/// [`alloc_object`], which resolves rsrcsrv lazily through
/// [`crate::client::caps::rsrcsrv_ep`] (a cached `NAMESRV_LOOKUP("rsrcsrv")`):
/// general services receive rsrcsrv via that lazy path rather than an eager
/// cap-table entry, so reading the `__trona_cap_rsrcsrv_ep` weak symbol
/// directly would observe 0 and fail. The returned object lives for the
/// process lifetime; its rsrcsrv `record_id` is intentionally dropped because
/// reactor objects are never individually freed (unlike per-client/per-session
/// allocations, which must thread the record through `free_record`).
///
/// Returns `None` if rsrcsrv cannot be resolved, a slot cannot be allocated,
/// or rsrcsrv rejects the request.
pub fn rsrc_alloc_object(obj_type: u64, size_bits: u64) -> Option<OwnedCap> {
    // SAFETY: `alloc_object` lands the minted cap into a freshly allocated,
    // solely-owned global-allocator slot — exactly `adopt_received`'s contract.
    alloc_object(obj_type, size_bits)
        .ok()
        .map(|slot| unsafe { OwnedCap::adopt_received(slot) })
}
