// SPDX-License-Identifier: GPL-2.0-only
//
//! Receive-slot arena — segment-backed pool of CNode slots that the
//! server-loop arms as the IPC receive destination.
//!
//! Owns one active segment at a time — a contiguous run of CNode
//! slots reserved through an injected `SlotAllocator`. Exactly one
//! slot is "current", armed for the next receive. On each
//! server-loop iteration, [`RecvSlotArena::recycle_for_next_recv`]
//! either advances to a fresh slot (when the previous one was kept
//! by a handler via [`RecvSlotArena::mark_kept`] or
//! [`capture_transferred_cap`]) or `cnode_delete`s any stray cap
//! and re-arms the same slot. When the active segment exhausts the
//! arena calls the injected allocator for a new segment of the same
//! initial size; retained caps in earlier segments stay live where
//! the handlers placed them.
//!
//! # Allocator injection
//!
//! `RecvSlotArena` is part of `trona_server` and must not depend on
//! `trona_runtime`. The two callbacks below let any runtime plug its
//! slot allocator state in without dragging the dependency into this
//! crate. Server binaries compose a `SlotAllocator` directly:
//!
//! ```ignore
//! const RUNTIME_SLOT_ALLOCATOR: trona_server::recv_slot::SlotAllocator =
//!     trona_server::recv_slot::SlotAllocator {
//!         alloc_consecutive: trona_runtime::core::slot_alloc::slot_alloc_consecutive_cb,
//!         invoke_depth: trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
//!     };
//! ```
//!
//! and pass it through [`RecvSlotArena::init_with_allocator`] at
//! startup. The runtime crate itself holds no reference to
//! `RecvSlotArena` — the composition root lives in each server's
//! `main`, which is the only crate that depends on both `trona_runtime`
//! and `trona_server`.
//!
//! # Cap-count trust
//!
//! [`capture_transferred_cap`] consults the kernel-published
//! `received_cap_count` in
//! `ipc_buffer.reserved[KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT]`
//! (via [`trona_kernel::ipc_buffer::read_received_cap_count`]) and
//! returns `None` when the kernel reports no caps transferred —
//! callers no longer rely on the sender's label contract to gate
//! the keep.

use trona_kernel::core_types::{Cap, CapRef, IpcContext};
use trona_kernel::invoke;
use trona_kernel::ipc;

/// Allocate `count` consecutive CNode slots in the calling
/// process's CSpace. Returns the base slot or `None` when the
/// allocator is exhausted. `unsafe` because the implementation
/// typically reaches into thread-shared runtime state.
pub type SlotAllocConsecutive = unsafe fn(count: u64) -> Option<u64>;

/// Resolve the invoke depth for `slot` rooted at the caller's
/// own CSpace (`KERNITE_CAP_SELF_CSPACE`). Returns `0` for the
/// flat root CNode and a positive depth for slots living inside
/// a slot-allocator-managed expansion segment.
pub type SlotInvokeDepth = unsafe fn(slot: u64) -> u8;

/// Two-callback allocator handle injected into `RecvSlotArena`.
/// Composed in the runtime crate; `RecvSlotArena` only sees the
/// function pointers.
#[derive(Clone, Copy)]
pub struct SlotAllocator {
    pub alloc_consecutive: SlotAllocConsecutive,
    pub invoke_depth: SlotInvokeDepth,
}

impl SlotAllocator {
    /// Convenience for `static mut RecvSlotArena` init: a placeholder
    /// allocator that always reports exhaustion. `RecvSlotArena`
    /// configured with this never grows; legitimate use is only as a
    /// pre-`init_with_allocator` sentinel.
    pub const fn unconfigured() -> Self {
        unsafe fn fail_alloc(_count: u64) -> Option<u64> {
            None
        }
        unsafe fn fail_depth(_slot: u64) -> u8 {
            0
        }
        Self {
            alloc_consecutive: fail_alloc,
            invoke_depth: fail_depth,
        }
    }
}

/// Fixed receive-window manager for servers whose receive slots are
/// reserved by their bootstrap layout instead of by [`RecvSlotArena`].
///
/// The window is scratch ownership: handlers must move any cap that
/// survives the current dispatch into an owned slot before returning.
/// `arm_fixed_recv_window` clears the whole window before staging it as
/// the next IPC receive destination, so stale payload caps
/// cannot make the kernel report `KERNITE_ERR_SLOT_OCCUPIED` forever.
#[derive(Clone, Copy)]
pub struct FixedRecvWindow {
    base: Cap,
    len: u64,
    invoke_depth: SlotInvokeDepth,
}

impl FixedRecvWindow {
    pub const fn new(base: Cap, len: u64, invoke_depth: SlotInvokeDepth) -> Self {
        Self {
            base,
            len,
            invoke_depth,
        }
    }

    #[inline]
    pub fn base(&self) -> Cap {
        self.base
    }

    #[inline]
    pub fn slot(&self, idx: u64) -> Cap {
        self.base + idx
    }

    /// Delete every cap currently sitting in the scratch window.
    ///
    /// # Safety
    ///
    /// The caller must own the CSpace rooted by `cspace`; no live cap may
    /// remain in the scratch window unless it is intentionally being
    /// discarded.
    pub unsafe fn clear(&self, cspace: Cap) {
        unsafe { clear_fixed_recv_window(cspace, self.base, self.len, self.invoke_depth) };
    }

    /// Clear and arm the window as `ctx`'s next receive destination.
    ///
    /// # Safety
    ///
    /// `ctx` must be the current thread's IPC context. Any cap that must
    /// outlive the previous dispatch must already have been moved out of
    /// this window.
    pub unsafe fn arm(&self, ctx: *mut IpcContext, cspace: Cap) {
        unsafe { arm_fixed_recv_window(ctx, cspace, self.base, self.len, self.invoke_depth) };
    }
}

/// Clear a fixed scratch window.
///
/// # Safety
///
/// The caller must own the destination CSpace and must have moved every
/// live cap out of `[base, base + len)` before calling.
pub unsafe fn clear_fixed_recv_window(
    cspace: Cap,
    base: Cap,
    len: u64,
    invoke_depth: SlotInvokeDepth,
) {
    for idx in 0..len {
        let slot = base + idx;
        let depth = unsafe { invoke_depth(slot) };
        let _ = invoke::cnode_delete_depth(CapRef::flat(cspace), slot, depth);
    }
}

/// Clear and arm a fixed receive window for the next `MP_READ`.
///
/// # Safety
///
/// `ctx` must point at the calling thread's IPC context. See
/// [`clear_fixed_recv_window`] for the scratch ownership rule.
pub unsafe fn arm_fixed_recv_window(
    ctx: *mut IpcContext,
    cspace: Cap,
    base: Cap,
    len: u64,
    invoke_depth: SlotInvokeDepth,
) {
    if ctx.is_null() || base == 0 || len == 0 {
        return;
    }
    unsafe { clear_fixed_recv_window(cspace, base, len, invoke_depth) };
    let depth = unsafe { invoke_depth(base) };
    unsafe {
        ipc::set_receive_slot_path_ctx(ctx, cspace, base, 0, depth as u64);
    }
}

/// Arena managing per-recv capability destination slots.
pub struct RecvSlotArena {
    base: Cap,
    end: Cap,
    next: Cap,
    current: Cap,
    kept: bool,
    /// Size of every segment in slots — captured at
    /// `init_with_allocator` time and reused for every dynamic grow
    /// so each new segment matches the caller's expected arena
    /// footprint.
    segment_size: u64,
    /// Injected slot allocator + invoke-depth resolver. Configured
    /// once via `init_with_allocator`; subsequent `grow_segment` and
    /// `set_receive_slot_path_ctx` calls dispatch through it.
    allocator: SlotAllocator,
}

impl RecvSlotArena {
    /// A zeroed arena suitable for `static mut` initialisation. Must
    /// be populated by [`Self::init_with_allocator`] before use.
    pub const fn new_empty() -> Self {
        Self {
            base: 0,
            end: 0,
            next: 0,
            current: 0,
            kept: false,
            segment_size: 0,
            allocator: SlotAllocator::unconfigured(),
        }
    }

    /// Reserve `cap_count` consecutive CNode slots through `allocator`
    /// and install them as this arena's first segment. The first slot
    /// becomes `current`, ready to arm via [`Self::arm_first`].
    /// `cap_count` is also captured as the size used for every
    /// subsequent dynamic grow.
    ///
    /// Returns `false` when `cap_count` is zero or the allocator
    /// cannot satisfy the request — callers that need cap reception
    /// should treat this as fatal (the arena stays empty).
    ///
    /// # Safety
    ///
    /// Must be called exactly once per arena, before any of the
    /// other methods or [`capture_transferred_cap`] are invoked.
    /// `allocator`'s underlying state must already be initialised;
    /// when composing from `trona_runtime`, that means the runtime
    /// slot allocator (`runtime_init_slot_allocator`) has run as
    /// part of crt / rtld startup before `main`.
    pub unsafe fn init_with_allocator(&mut self, allocator: SlotAllocator, cap_count: u64) -> bool {
        if cap_count == 0 {
            return false;
        }
        let base = match unsafe { (allocator.alloc_consecutive)(cap_count) } {
            Some(b) => b,
            None => return false,
        };
        self.base = base;
        self.end = base + cap_count;
        self.next = base + 1;
        self.current = base;
        self.kept = false;
        self.segment_size = cap_count;
        self.allocator = allocator;
        true
    }

    /// The slot currently armed as the IPC receive destination.
    #[inline]
    pub fn current(&self) -> Cap {
        self.current
    }

    /// Flag the current slot as retained by a handler. The next
    /// [`Self::recycle_for_next_recv`] advances to a fresh slot
    /// instead of deleting the current one.
    #[inline]
    pub fn mark_kept(&mut self) {
        self.kept = true;
    }

    /// Arm `current` as the receive destination on `ctx`. Call once
    /// before the first `mp_read_ctx`; subsequent iterations use
    /// [`Self::recycle_for_next_recv`].
    ///
    /// # Safety
    ///
    /// `ctx` must be a valid, initialised IPC context. `cspace` must
    /// be the caller's own CSpace root (typically
    /// `CAP_SELF_CSPACE`).
    pub unsafe fn arm_first(&mut self, ctx: *mut IpcContext, cspace: Cap) {
        if self.current == 0 {
            return;
        }
        let depth = unsafe { (self.allocator.invoke_depth)(self.current) };
        unsafe {
            ipc::set_receive_slot_path_ctx(ctx, cspace, self.current, 0, depth as u64);
        }
    }

    /// Allocate a fresh segment of `segment_size` slots through the
    /// injected allocator and migrate `current` into it. Returns
    /// `false` when the allocator is exhausted; the active segment
    /// stays unchanged so the caller can keep using it (typically by
    /// re-arming the last slot after deleting whatever's there).
    ///
    /// # Safety
    ///
    /// Called by `recycle_for_next_recv` when the current segment
    /// exhausts (`next == end`), with no other concurrent access to
    /// this arena.
    unsafe fn grow_segment(&mut self) -> bool {
        if self.segment_size == 0 {
            return false;
        }
        let base = match unsafe { (self.allocator.alloc_consecutive)(self.segment_size) } {
            Some(b) => b,
            None => return false,
        };
        self.base = base;
        self.end = base + self.segment_size;
        self.next = base + 1;
        self.current = base;
        true
    }

    /// Between server-loop iterations: consume the kept flag and
    /// re-arm.
    ///
    /// - `kept == true` → advance `current` to a fresh arena slot.
    ///   When the active segment exhausts (`next == end`), allocate
    ///   a fresh segment via the injected allocator and continue;
    ///   retained caps in the prior segment stay where the handlers
    ///   stored them. Allocator exhaustion falls back to re-using the
    ///   last slot.
    /// - `kept == false` → `cnode_delete` any stray cap at the
    ///   current slot (errors ignored — the goal is only to
    ///   guarantee the slot is empty before the next receive) and
    ///   re-arm the same slot.
    ///
    /// # Safety
    ///
    /// `ctx` must be a valid IPC context. `cspace` must be the
    /// caller's CSpace root.
    pub unsafe fn recycle_for_next_recv(&mut self, ctx: *mut IpcContext, cspace: Cap) {
        if self.current == 0 {
            return;
        }
        if self.kept {
            self.kept = false;
            if self.next < self.end {
                self.current = self.next;
                self.next += 1;
            } else {
                let _ = unsafe { self.grow_segment() };
            }
        } else {
            // `cnode_delete` lives in `trona_runtime::core::cnode` —
            // server crate cannot call it. Use `cnode_delete_depth`
            // (raw, depth-explicit form) directly so we stay inside
            // `trona_kernel`.
            let depth = unsafe { (self.allocator.invoke_depth)(self.current) };
            if depth == 0 {
                let _ = invoke::cnode_delete_depth(CapRef::flat(cspace), self.current, 0);
            } else {
                let _ = invoke::cnode_delete_depth(CapRef::flat(cspace), self.current, depth);
            }
        }
        let depth = unsafe { (self.allocator.invoke_depth)(self.current) };
        unsafe {
            ipc::set_receive_slot_path_ctx(ctx, cspace, self.current, 0, depth as u64);
        }
    }
}

/// Capture the capability the most recent inbound IPC transferred
/// into `arena.current`.
///
/// Reads the kernel-published `received_cap_count` from
/// `ipc_buffer.reserved[KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT]`
/// (via [`trona_kernel::ipc_buffer::read_received_cap_count`]) and
/// returns `None` when the kernel reports no caps transferred —
/// callers no longer rely on the sender's label contract to gate
/// the keep.
///
/// On a positive cap count, marks the slot kept and returns its
/// index. The caller owns the cap at that slot and must arrange for
/// its lifecycle (typically storing the slot in per-service state
/// and `cnode_delete`-ing any previously held cap on replacement).
/// A runtime caller that keeps owned-cap state instead wraps the
/// returned slot with `OwnedCap::adopt_received` (trona_runtime) and
/// stores the resulting handle; it must not *also* retain the raw slot,
/// or teardown would delete the same cap twice.
/// Returns `None` when the arena is uninitialised (`current == 0`)
/// or the IPC context / buffer is null — those are programming
/// errors and the caller should fail loudly.
///
/// # Safety
///
/// `ctx` must be a valid IPC context (typically the same one the
/// caller passed to `mp_read_ctx` / `mp_write_reply_read_ctx`). The most
/// recent receive on this context must have completed successfully.
pub unsafe fn capture_transferred_cap(
    ctx: *mut IpcContext,
    arena: &mut RecvSlotArena,
) -> Option<Cap> {
    if ctx.is_null() {
        return None;
    }
    let buf = unsafe { (*ctx).ipc_buffer };
    if buf.is_null() {
        return None;
    }
    let cap_count = unsafe { trona_kernel::ipc_buffer::read_received_cap_count(buf as *const _) };
    if cap_count == 0 {
        return None;
    }
    let slot = arena.current();
    if slot == 0 {
        return None;
    }
    arena.mark_kept();
    Some(slot)
}
