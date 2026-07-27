// SPDX-License-Identifier: GPL-2.0-only
//
//! Typed capability invocation wrappers.
//!
//! Each function below names one `(cap_type, invoke_label)` pair so
//! callers do not have to thread raw labels through. The kernel
//! exposes a single trap (`KERNITE_SYS_INVOKE`); every wrapper here
//! routes through `crate::syscall::invoke`.

use crate::core_types::{CapRef, IpcContext};
use crate::syscall::invoke;

/// Initial stack pointer for entering a Rust/C ABI function by
/// directly programming a TCB's RIP/RSP, rather than arriving via a
/// machine `call`.
///
/// On x86_64 SysV, function entry observes `RSP % 16 == 8` because
/// the call instruction has pushed an 8-byte return address. A TCB
/// starter jumps directly, so callers that use a raw function as
/// `entry_rip` must bias the top-of-stack by 8 bytes or LLVM may emit
/// aligned stack stores that fault. Other supported ABIs keep the
/// stack naturally aligned at entry.
#[cfg(target_arch = "x86_64")]
#[inline]
pub const fn direct_entry_rsp(stack_top: u64) -> u64 {
    stack_top.wrapping_sub(8)
}

/// Initial stack pointer for entering a Rust/C ABI function by
/// directly programming a TCB's RIP/RSP, rather than arriving via a
/// machine `call`.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub const fn direct_entry_rsp(stack_top: u64) -> u64 {
    stack_top
}

// ---------------------------------------------------------------------------
// Untyped operations.
// ---------------------------------------------------------------------------

/// Retype raw memory from `untyped` into a new kernel object of
/// `new_type` with `size_bits` (0 = default), placing the resulting
/// cap at `dest_slot`.
pub fn untyped_retype(untyped: CapRef, new_type: u64, size_bits: u64, dest_slot: u64) -> i32 {
    invoke(
        untyped.addr(),
        uapi::KERNITE_INV_UNTYPED_RETYPE as u64,
        new_type,
        size_bits,
        dest_slot,
        0,
    )
    .error as i32
}

/// Reset an exhausted untyped once all typed children have been
/// destroyed.
pub fn untyped_reset(untyped: CapRef) -> i32 {
    invoke(
        untyped.addr(),
        uapi::KERNITE_INV_UNTYPED_RESET as u64,
        0,
        0,
        0,
        0,
    )
    .error as i32
}

/// Retype with explicit CNode depth (for expanded CSpace hierarchy).
pub fn untyped_retype_depth(
    untyped: CapRef,
    new_type: u64,
    size_bits: u64,
    dest_slot: u64,
    dest_depth: u8,
) -> i32 {
    write_invoke_depth(dest_depth, 0);
    untyped_retype(untyped, new_type, size_bits, dest_slot)
}

// ---------------------------------------------------------------------------
// TCB operations.
//
// task_start / task_stop / task_kill replace the legacy
// resume/suspend pair. Notification-bound TCB operations are gone
// (the new event plane composes those via EventQueue + Watch).
// ---------------------------------------------------------------------------

/// Configure a TCB's instruction pointer, stack pointer, and IPC
/// buffer address.
pub fn tcb_configure(tcb: CapRef, rip: u64, rsp: u64, ipc_buf: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_CONFIGURE as u64,
        rip,
        rsp,
        ipc_buf,
        0,
    )
    .error as i32
}

/// Mark a TCB schedulable. Replaces the legacy `tcb_resume`.
pub fn tcb_start(tcb: CapRef) -> i32 {
    invoke(tcb.addr(), uapi::KERNITE_INV_TCB_START as u64, 0, 0, 0, 0).error as i32
}

/// Park a TCB at the next safe point and remove it from the
/// scheduler ready queue. Replaces the legacy `tcb_suspend`.
pub fn tcb_stop(tcb: CapRef) -> i32 {
    invoke(tcb.addr(), uapi::KERNITE_INV_TCB_STOP as u64, 0, 0, 0, 0).error as i32
}

/// Drive a TCB into terminal `Dying` state. Replaces the legacy
/// fault-handler-driven exit path.
pub fn tcb_kill(tcb: CapRef) -> i32 {
    invoke(tcb.addr(), uapi::KERNITE_INV_TCB_KILL as u64, 0, 0, 0, 0).error as i32
}

/// Set a TCB's CSpace and VSpace root capabilities.
pub fn tcb_set_space(tcb: CapRef, cspace: CapRef, vspace: CapRef) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_SPACE as u64,
        cspace.addr(),
        vspace.addr(),
        0,
        0,
    )
    .error as i32
}

/// Set a TCB's CSpace and VSpace with explicit CNode depth.
pub fn tcb_set_space_with_depth(tcb: CapRef, cspace: CapRef, vspace: CapRef, depth: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_SPACE as u64,
        cspace.addr(),
        vspace.addr(),
        depth,
        0,
    )
    .error as i32
}

/// Bind the fault MessagePipe for this TCB. Page faults / illegal
/// instructions / breakpoints / OOM / cap faults are synthesised as
/// MP records and written to this pipe. Pass `0` to clear.
pub fn tcb_set_fault_pipe(tcb: CapRef, fault_mp: CapRef) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_FAULT_PIPE as u64,
        fault_mp.addr(),
        0,
        0,
        0,
    )
    .error as i32
}

/// Set the IPC buffer virtual address for a TCB.
pub fn tcb_set_ipc_buffer(tcb: CapRef, addr: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_IPC_BUFFER as u64,
        addr,
        0,
        0,
        0,
    )
    .error as i32
}

/// Write a TCB's instruction pointer and stack pointer.
pub fn tcb_write_registers(tcb: CapRef, flags: u64, rip: u64, rsp: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_WRITE_REGISTERS as u64,
        flags,
        rip,
        rsp,
        0,
    )
    .error as i32
}

/// Set a class-local scheduling priority for a TCB.
pub fn tcb_set_priority(tcb: CapRef, priority: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_PRIORITY as u64,
        priority,
        0,
        0,
        0,
    )
    .error as i32
}

/// Copy FPU/SSE state from source TCB to destination TCB. Used
/// during fork to preserve the parent's floating-point state.
pub fn tcb_copy_fpu(dest_tcb: CapRef, src_tcb: CapRef) -> i32 {
    invoke(
        dest_tcb.addr(),
        uapi::KERNITE_INV_TCB_COPY_FPU as u64,
        src_tcb.addr(),
        0,
        0,
        0,
    )
    .error as i32
}

/// Set the TLS base address (FS_BASE on x86_64, TPIDR_EL0 on
/// aarch64) for a TCB.
pub fn tcb_set_tls_base(tcb: CapRef, tls_base: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_TLS_BASE as u64,
        tls_base,
        0,
        0,
        0,
    )
    .error as i32
}

/// Set the process ABI thread pointer (GS_BASE on x86_64, x18 on aarch64).
pub fn tcb_set_abi_tp(tcb: CapRef, abi_tp: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_ABI_TP as u64,
        abi_tp,
        0,
        0,
        0,
    )
    .error as i32
}

/// Publish the thread's usable stack reserve bounds. `stack_top` is
/// exclusive, `stack_min` is inclusive, both page-aligned.
/// `guard_bottom` is the inclusive lower bound of the unmapped guard
/// hole (0 = no guard tracked).
pub fn tcb_set_stack_bounds(tcb: CapRef, stack_top: u64, stack_min: u64, guard_bottom: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_STACK_BOUNDS as u64,
        stack_top,
        stack_min,
        guard_bottom,
        0,
    )
    .error as i32
}

/// Select the scheduler class for a TCB.
pub fn tcb_set_sched_class(tcb: CapRef, sched_class: u64) -> i32 {
    invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_SET_SCHED_CLASS as u64,
        sched_class,
        0,
        0,
        0,
    )
    .error as i32
}

/// Query the CSpace depth of a TCB. The kernel writes the depth to
/// IPC buffer `msg[0]`. Returns `Some(depth)` on success.
///
/// # Safety
/// `ctx` must point to the caller's live IPC context for the current
/// thread. The underlying IPC buffer must stay mapped for the duration
/// of the invocation.
pub unsafe fn tcb_get_space_info_ctx(ctx: *mut IpcContext, tcb: CapRef) -> Option<u8> {
    let r = invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_GET_SPACE_INFO as u64,
        0,
        0,
        0,
        0,
    );
    if r.error != 0 {
        return None;
    }
    unsafe {
        if ctx.is_null() {
            return None;
        }
        let ipc_buffer = (*ctx).ipc_buffer;
        if ipc_buffer.is_null() {
            return None;
        }
        Some((*ipc_buffer).msg[0] as u8)
    }
}

/// Read cumulative CPU runtime counters for `tcb`. Reply is written
/// to IPC buffer `msg[0]` (user_ns) and `msg[1]` (system_ns).
///
/// # Safety
/// `ctx` must point to the caller's live IPC context for the current
/// thread. The underlying IPC buffer must stay mapped for the duration
/// of the invocation.
pub unsafe fn tcb_get_cpu_times_ctx(ctx: *mut IpcContext, tcb: CapRef) -> Option<(u64, u64)> {
    let r = invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_GET_CPU_TIMES as u64,
        0,
        0,
        0,
        0,
    );
    if r.error != 0 {
        return None;
    }
    unsafe {
        if ctx.is_null() {
            return None;
        }
        let ipc_buffer = (*ctx).ipc_buffer;
        if ipc_buffer.is_null() {
            return None;
        }
        Some(((*ipc_buffer).msg[0], (*ipc_buffer).msg[1]))
    }
}

/// Read the target TCB's stable kernel trace id.
pub fn tcb_get_trace_id(tcb: CapRef) -> Option<u64> {
    let r = invoke(
        tcb.addr(),
        uapi::KERNITE_INV_TCB_GET_TRACE_ID as u64,
        0,
        0,
        0,
        0,
    );
    if r.error != 0 { None } else { Some(r.value) }
}

// ---------------------------------------------------------------------------
// SchedContext operations.
// ---------------------------------------------------------------------------

/// Configure a scheduling context with budget and period
/// (nanoseconds).
pub fn sc_configure(sc: CapRef, budget_ns: u64, period_ns: u64) -> i32 {
    invoke(
        sc.addr(),
        uapi::KERNITE_INV_SC_CONFIGURE as u64,
        budget_ns,
        period_ns,
        0,
        0,
    )
    .error as i32
}

/// Bind a scheduling context to a TCB.
pub fn sc_bind(sc: CapRef, tcb: CapRef) -> i32 {
    invoke(
        sc.addr(),
        uapi::KERNITE_INV_SC_BIND as u64,
        tcb.addr(),
        0,
        0,
        0,
    )
    .error as i32
}

// ---------------------------------------------------------------------------
// VSpace operations.
// ---------------------------------------------------------------------------

/// Map a frame capability at `vaddr` in the given VSpace with
/// `flags` (`VSPACE_FLAG_WRITABLE` / `_USER` / `_EXECUTABLE` / ...).
pub fn vspace_map(vspace: CapRef, frame: CapRef, vaddr: u64, flags: u64) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_MAP as u64,
        frame.addr(),
        vaddr,
        flags,
        0,
    )
    .error as i32
}

/// Snapshot the VSpace's per-process memory accounting counters
/// into `*out_uaddr`. Returns 0 on success or a `KERNITE_ERR_*` code.
///
/// Raw form — caller passes a userland address as `u64`. Typed
/// wrapper lives in `trona_runtime::core::vspace_ext`. Long-term the
/// `TronaVSpaceMemStats` shape will be promoted to `uapi` so this can
/// take a typed pointer directly.
pub fn vspace_get_mem_stats_raw(vspace: CapRef, out_uaddr: u64) -> u64 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_GET_MEM_STATS as u64,
        out_uaddr,
        0,
        0,
        0,
    )
    .error
}

/// Snapshot resident / share / dirty / PSS stats for a VSpace
/// range into `*out_uaddr`. Raw form — see `vspace_get_mem_stats_raw`.
pub fn vspace_get_range_stats_raw(
    vspace: CapRef,
    start_vaddr: u64,
    page_count: u64,
    out_uaddr: u64,
) -> u64 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_GET_RANGE_STATS as u64,
        start_vaddr,
        page_count,
        out_uaddr,
        0,
    )
    .error
}

/// Read the target VSpace's stable kernel trace id.
pub fn vspace_get_trace_id(vspace: CapRef) -> Option<u64> {
    let r = invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_GET_TRACE_ID as u64,
        0,
        0,
        0,
        0,
    );
    if r.error != 0 { None } else { Some(r.value) }
}

/// Unmap the page at `vaddr` from the given VSpace.
pub fn vspace_unmap(vspace: CapRef, vaddr: u64) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_UNMAP as u64,
        vaddr,
        0,
        0,
        0,
    )
    .error as i32
}

/// Change protection flags on the page at `vaddr` in the given
/// VSpace.
pub fn vspace_protect(vspace: CapRef, vaddr: u64, flags: u64) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_PROTECT as u64,
        vaddr,
        flags,
        0,
        0,
    )
    .error as i32
}

/// Change protection flags on a contiguous range of pages.
pub fn vspace_protect_range(vspace: CapRef, vaddr: u64, count: u64, flags: u64) -> (i32, u64) {
    let r = invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_PROTECT_RANGE as u64,
        vaddr,
        count,
        flags,
        0,
    );
    (r.error as i32, r.value)
}

/// Map an intermediate page table at the given level for `vaddr`. `page_table`
/// must be a `PageTable` cap (not a `Frame`) — see `VSPACE_MAP_PT`.
pub fn vspace_map_pt(vspace: CapRef, page_table: CapRef, vaddr: u64, level: u64) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_MAP_PT as u64,
        page_table.addr(),
        vaddr,
        level,
        0,
    )
    .error as i32
}

/// Walk the page table starting at `start_vaddr`, returning up to
/// `max_entries` mapping entries via the IPC buffer.
pub fn vspace_walk(vspace: CapRef, start_vaddr: u64, max_entries: u64) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_WALK as u64,
        start_vaddr,
        max_entries,
        0,
        0,
    )
    .error as i32
}

/// Resolve exactly `vaddr` in `vspace` to a present physical address.
/// Unlike `vspace_walk`, this does not advance to the next present
/// mapping when `vaddr` itself is unmapped or demand-only.
pub fn vspace_resolve_page(vspace: CapRef, vaddr: u64) -> (i32, u64) {
    let r = invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_RESOLVE_PAGE as u64,
        vaddr,
        0,
        0,
        0,
    );
    (r.error as i32, r.value)
}

/// Start word offset in IPC buffer page for `VSPACE_WALK` tuples.
pub const VSPACE_WALK_ENTRY_BASE_WORD: usize = 42;
/// Tuple width in u64 words: `(vaddr, phys, flags)`.
pub const VSPACE_WALK_ENTRY_WORDS: usize = 3;

/// Read `(count, next_vaddr)` from the latest `VSPACE_WALK` result.
///
/// # Safety
/// `ctx` must point to the caller's live IPC context for the current
/// thread. The underlying IPC buffer must contain the result of the
/// most recent successful `vspace_walk` call.
#[inline]
pub unsafe fn vspace_walk_result_header_ctx(ctx: *mut IpcContext) -> Option<(u64, u64)> {
    unsafe {
        let ipc_words = walk_ipc_words_ctx(ctx)?;
        Some((
            ::core::ptr::read_volatile(ipc_words),
            ::core::ptr::read_volatile(ipc_words.add(1)),
        ))
    }
}

/// Read one `(vaddr, phys, flags)` tuple from the latest
/// `VSPACE_WALK` result.
///
/// # Safety
/// `ctx` must point to the caller's live IPC context for the current
/// thread. The underlying IPC buffer must contain the result of the
/// most recent successful `vspace_walk` call.
pub unsafe fn vspace_walk_result_entry_ctx(
    ctx: *mut IpcContext,
    index: usize,
) -> Option<(u64, u64, u64)> {
    unsafe {
        let ipc_words = walk_ipc_words_ctx(ctx)?;
        let offset =
            VSPACE_WALK_ENTRY_BASE_WORD.checked_add(index.checked_mul(VSPACE_WALK_ENTRY_WORDS)?)?;
        let ipc_words_total =
            ::core::mem::size_of::<uapi::kernite_ipc_buffer>() / ::core::mem::size_of::<u64>();
        if offset + 2 >= ipc_words_total {
            return None;
        }
        Some((
            ::core::ptr::read_volatile(ipc_words.add(offset)),
            ::core::ptr::read_volatile(ipc_words.add(offset + 1)),
            ::core::ptr::read_volatile(ipc_words.add(offset + 2)),
        ))
    }
}

#[inline]
unsafe fn walk_ipc_words_ctx(ctx: *mut IpcContext) -> Option<*const u64> {
    if ctx.is_null() {
        return None;
    }
    let ipc_buffer = unsafe { (*ctx).ipc_buffer };
    if ipc_buffer.is_null() {
        return None;
    }
    Some(ipc_buffer as *const u64)
}

/// Copy page contents from `src_vaddr` in `src_vspace` into
/// `dst_frame`.
pub fn vspace_copy_page(src_vspace: CapRef, src_vaddr: u64, dst_frame: CapRef) -> i32 {
    invoke(
        src_vspace.addr(),
        uapi::KERNITE_INV_VSPACE_COPY_PAGE as u64,
        src_vaddr,
        dst_frame.addr(),
        0,
        0,
    )
    .error as i32
}

/// Map a single 4 KiB page from a device untyped region into a
/// VSpace.
pub fn vspace_map_device(
    vspace: CapRef,
    device_untyped: CapRef,
    page_offset: u64,
    vaddr: u64,
    flags: u64,
) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_MAP_DEVICE as u64,
        device_untyped.addr(),
        page_offset,
        vaddr,
        flags,
    )
    .error as i32
}

/// Batch-map contiguous 4 KiB pages from a device untyped region.
/// Returns `(error, pages_mapped)`.
pub fn vspace_map_device_range(
    vspace: CapRef,
    device_untyped: CapRef,
    offset_start: u64,
    vaddr_start: u64,
    num_pages: u64,
    flags: u64,
) -> (i32, u64) {
    let count_and_flags = (num_pages << 32) | (flags & 0xFFFF_FFFF);
    let r = invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_MAP_DEVICE_RANGE as u64,
        device_untyped.addr(),
        offset_start,
        vaddr_start,
        count_and_flags,
    );
    (r.error as i32, r.value)
}

/// Share a read-only page from src VSpace to dst VSpace. Copies the
/// PTE only if present and read-only; returns non-zero for writable
/// or absent pages.
pub fn vspace_share_ro_page(
    src_vspace: CapRef,
    src_vaddr: u64,
    dst_vspace: CapRef,
    dst_vaddr: u64,
) -> i32 {
    invoke(
        src_vspace.addr(),
        uapi::KERNITE_INV_VSPACE_SHARE_RO_PAGE as u64,
        src_vaddr,
        dst_vspace.addr(),
        dst_vaddr,
        0,
    )
    .error as i32
}

/// Install a demand-page PTE at `vaddr` in the given VSpace.
pub fn vspace_map_demand(vspace: CapRef, vaddr: u64, flags: u64) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_MAP_DEMAND as u64,
        vaddr,
        flags,
        0,
        0,
    )
    .error as i32
}

/// Configure a pre-allocated frame pool for kernel-side COW
/// fast-path.
pub fn vspace_set_cow_pool(
    vspace: CapRef,
    pool_frame: CapRef,
    src_cnode: CapRef,
    count: u64,
) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_SET_COW_POOL as u64,
        pool_frame.addr(),
        src_cnode.addr(),
        count,
        0,
    )
    .error as i32
}

/// Replenish consumed pool entries with new Frame caps.
pub fn vspace_replenish_cow_pool(
    vspace: CapRef,
    src_cnode: CapRef,
    start_slot: u64,
    count: u64,
) -> i32 {
    invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_REPLENISH_COW_POOL as u64,
        src_cnode.addr(),
        start_slot,
        count,
        0,
    )
    .error as i32
}

/// Install demand-page PTEs for a contiguous range. Returns
/// `(error, pages_mapped)`.
pub fn vspace_map_demand_range(
    vspace: CapRef,
    vaddr_start: u64,
    count: u64,
    flags: u64,
) -> (i32, u64) {
    let r = invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_MAP_DEMAND_RANGE as u64,
        vaddr_start,
        count,
        flags,
        0,
    );
    (r.error as i32, r.value)
}

/// Fork a range of pages from parent VSpace (invoke target) to
/// child VSpace. All-or-nothing.
pub fn vspace_fork_range(
    parent_vspace: CapRef,
    child_vspace: CapRef,
    state: CapRef,
    parent_shadow_mo: CapRef,
    child_mo: CapRef,
    va_start: u64,
    rollback_buffer_uaddr: u64,
) -> (i32, u64) {
    // arg0 packs the child VSpace cap (low 32) and the per-tree VmHierarchyState
    // cap `S` (high 32) — the invoke registers are otherwise full and a cap slot
    // is 32-bit. arg1 packs the shadow + child MO caps the same way.
    let child_vs_s_packed =
        ((state.addr() & 0xFFFF_FFFF) << 32) | (child_vspace.addr() & 0xFFFF_FFFF);
    let packed_mo_caps =
        ((parent_shadow_mo.addr() & 0xFFFF_FFFF) << 32) | (child_mo.addr() & 0xFFFF_FFFF);
    let r = invoke(
        parent_vspace.addr(),
        uapi::KERNITE_INV_VSPACE_FORK_RANGE as u64,
        child_vs_s_packed,
        packed_mo_caps,
        va_start,
        rollback_buffer_uaddr,
    );
    (r.error as i32, r.value)
}

/// Reverse a previously successful `vspace_fork_range` chunk.
pub fn vspace_undo_fork_range(
    parent_vspace: CapRef,
    child_vspace: CapRef,
    parent_shadow_mo: CapRef,
    child_mo: CapRef,
    va_start: u64,
    rollback_buffer_uaddr: u64,
) -> i32 {
    let packed_mo_caps =
        ((parent_shadow_mo.addr() & 0xFFFF_FFFF) << 32) | (child_mo.addr() & 0xFFFF_FFFF);
    invoke(
        parent_vspace.addr(),
        uapi::KERNITE_INV_VSPACE_UNDO_FORK_RANGE as u64,
        child_vspace.addr(),
        packed_mo_caps,
        va_start,
        rollback_buffer_uaddr,
    )
    .error as i32
}

// ---------------------------------------------------------------------------
// CNode operations.
// ---------------------------------------------------------------------------

// Slot-allocator-aware variants (`cnode_copy / cnode_mint / cnode_move /
// cnode_mutate / cnode_delete / cnode_revoke`) live in
// `trona_runtime::core::cnode` — they consult the runtime slot
// allocator to dispatch between flat-CNode and depth-explicit invokes.
// `trona_kernel` exposes only the raw depth-explicit forms below.

/// Set the guard value and guard bits on a CNode.
pub fn cnode_set_guard(cnode: CapRef, guard: u64, guard_bits: u64) -> i32 {
    invoke(
        cnode.addr(),
        uapi::KERNITE_INV_CNODE_SET_GUARD as u64,
        guard,
        guard_bits,
        0,
        0,
    )
    .error as i32
}

/// Query CNode metadata via IPC buffer.
pub fn cnode_get_info(cnode: CapRef) -> crate::core_types::TronaResult {
    invoke(
        cnode.addr(),
        uapi::KERNITE_INV_CNODE_GET_INFO as u64,
        0,
        0,
        0,
        0,
    )
}

// ---------------------------------------------------------------------------
// IRQ / IoPort operations.
//
// In the new event plane, IRQ delivery binds to an EventQueue
// (`IRQ_BIND_EQ`) instead of a notification. `irq_handler_ack`
// re-enables the IRQ in the controller.
// ---------------------------------------------------------------------------

/// Bind an IRQ handler to an EventQueue. Subsequent IRQ assertions
/// enqueue an `EVENT_TYPE_IRQ` record (carrying `cookie`) on the bound EQ.
pub fn irq_bind_eq(irq_handler: CapRef, eq: CapRef, cookie: u64) -> i32 {
    invoke(
        irq_handler.addr(),
        uapi::KERNITE_INV_IRQ_BIND_EQ as u64,
        eq.addr(),
        cookie,
        0,
        0,
    )
    .error as i32
}

/// Detach an IRQ handler from any bound EventQueue.
pub fn irq_unbind_eq(irq_handler: CapRef) -> i32 {
    invoke(
        irq_handler.addr(),
        uapi::KERNITE_INV_IRQ_UNBIND_EQ as u64,
        0,
        0,
        0,
        0,
    )
    .error as i32
}

/// Acknowledge an IRQ (re-enable it in the interrupt controller).
pub fn irq_ack(irq_handler: CapRef) -> i32 {
    invoke(
        irq_handler.addr(),
        uapi::KERNITE_INV_IRQ_ACK as u64,
        0,
        0,
        0,
        0,
    )
    .error as i32
}

pub fn irq_handler_ack(irq_handler: CapRef) -> i32 {
    irq_ack(irq_handler)
}

/// Read an 8-bit value from an I/O port. `port` is the absolute I/O
/// port number and must lie within the cap's `IoPortRange`. Returns
/// the kernel `SyscallError` (as `i32`) on rejection.
pub fn ioport_read_8(ioport: CapRef, port: u64) -> Result<u8, i32> {
    let r = invoke(
        ioport.addr(),
        uapi::KERNITE_INV_IOPORT_READ_8 as u64,
        port,
        0,
        0,
        0,
    );
    if r.error != 0 {
        Err(r.error as i32)
    } else {
        Ok(r.value as u8)
    }
}

pub fn ioport_in8(ioport: CapRef, port: u64) -> Result<u8, i32> {
    ioport_read_8(ioport, port)
}

/// Write an 8-bit value to an I/O port. `port` is the absolute I/O
/// port number and must lie within the cap's `IoPortRange`.
pub fn ioport_write_8(ioport: CapRef, port: u64, value: u8) -> Result<(), i32> {
    let r = invoke(
        ioport.addr(),
        uapi::KERNITE_INV_IOPORT_WRITE_8 as u64,
        port,
        value as u64,
        0,
        0,
    );
    if r.error != 0 {
        Err(r.error as i32)
    } else {
        Ok(())
    }
}

pub fn ioport_out8(ioport: CapRef, port: u64, value: u8) -> Result<(), i32> {
    ioport_write_8(ioport, port, value)
}

/// Read a 16-bit value from an I/O port. `port` is the absolute I/O
/// port number and must lie within the cap's `IoPortRange`.
pub fn ioport_read_16(ioport: CapRef, port: u64) -> Result<u16, i32> {
    let r = invoke(
        ioport.addr(),
        uapi::KERNITE_INV_IOPORT_READ_16 as u64,
        port,
        0,
        0,
        0,
    );
    if r.error != 0 {
        Err(r.error as i32)
    } else {
        Ok(r.value as u16)
    }
}

pub fn ioport_in16(ioport: CapRef, port: u64) -> Result<u16, i32> {
    ioport_read_16(ioport, port)
}

/// Write a 16-bit value to an I/O port. `port` is the absolute I/O
/// port number and must lie within the cap's `IoPortRange`.
pub fn ioport_write_16(ioport: CapRef, port: u64, value: u16) -> Result<(), i32> {
    let r = invoke(
        ioport.addr(),
        uapi::KERNITE_INV_IOPORT_WRITE_16 as u64,
        port,
        value as u64,
        0,
        0,
    );
    if r.error != 0 {
        Err(r.error as i32)
    } else {
        Ok(())
    }
}

pub fn ioport_out16(ioport: CapRef, port: u64, value: u16) -> Result<(), i32> {
    ioport_write_16(ioport, port, value)
}

/// Read a 32-bit value from an I/O port. `port` is the absolute I/O
/// port number and must lie within the cap's `IoPortRange`.
pub fn ioport_read_32(ioport: CapRef, port: u64) -> Result<u32, i32> {
    let r = invoke(
        ioport.addr(),
        uapi::KERNITE_INV_IOPORT_READ_32 as u64,
        port,
        0,
        0,
        0,
    );
    if r.error != 0 {
        Err(r.error as i32)
    } else {
        Ok(r.value as u32)
    }
}

pub fn ioport_in32(ioport: CapRef, port: u64) -> Result<u32, i32> {
    ioport_read_32(ioport, port)
}

/// Write a 32-bit value to an I/O port. `port` is the absolute I/O
/// port number and must lie within the cap's `IoPortRange`.
pub fn ioport_write_32(ioport: CapRef, port: u64, value: u32) -> Result<(), i32> {
    let r = invoke(
        ioport.addr(),
        uapi::KERNITE_INV_IOPORT_WRITE_32 as u64,
        port,
        value as u64,
        0,
        0,
    );
    if r.error != 0 {
        Err(r.error as i32)
    } else {
        Ok(())
    }
}

pub fn ioport_out32(ioport: CapRef, port: u64, value: u32) -> Result<(), i32> {
    ioport_write_32(ioport, port, value)
}

// ---------------------------------------------------------------------------
// MemoryObject operations.
// ---------------------------------------------------------------------------

/// Commit `count` pages starting at `offset` in a MemoryObject.
/// Status-only (Zircon `zx_vmo_op_range` model): returns `0` iff every requested
/// page is resident-or-populated, else the first error. No count, no rollback.
pub fn mo_commit(mo: CapRef, offset: u64, count: u64, ut_cap: u64) -> i32 {
    invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_COMMIT as u64,
        offset,
        count,
        ut_cap,
        0,
    )
    .error as i32
}

/// Decommit `count` pages starting at `offset`.
pub fn mo_decommit(mo: CapRef, offset: u64, count: u64) -> i32 {
    invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_DECOMMIT as u64,
        offset,
        count,
        0,
        0,
    )
    .error as i32
}

/// Get the page count of a MemoryObject.
pub fn mo_get_size(mo: CapRef) -> (i32, u64) {
    let r = invoke(mo.addr(), uapi::KERNITE_INV_MO_GET_SIZE as u64, 0, 0, 0, 0);
    (r.error as i32, r.value)
}

/// Initialize an existing child MemoryObject as a COW clone of `mo`.
pub fn mo_clone(mo: CapRef, child_mo: CapRef, flags: u64, state: CapRef) -> i32 {
    // arg2 is the per-tree VmHierarchyState `S` — required to bind a standalone
    // parent into a fresh COW tree; ignored (and reaped by the caller) when the
    // parent is already bound.
    invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_CLONE as u64,
        child_mo.addr(),
        flags,
        state.addr(),
        0,
    )
    .error as i32
}

/// Initialize an existing child MemoryObject as a COW clone of a
/// **sub-range** of `mo`: `child_page_count` pages starting `offset_pages`
/// into the parent. The child resolves uncommitted pages through `mo`'s
/// pager at the parent-relative offset (`page_idx + offset_pages`).
/// `state` is the per-tree VmHierarchyState `S` — required to bind a
/// standalone parent into a fresh COW tree; ignored (and reaped by the
/// caller) when the parent is already bound.
pub fn mo_clone_range(
    mo: CapRef,
    child_mo: CapRef,
    offset_pages: u64,
    child_page_count: u64,
    state: CapRef,
) -> i32 {
    invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_CLONE_RANGE as u64,
        child_mo.addr(),
        offset_pages,
        child_page_count,
        state.addr(),
    )
    .error as i32
}

/// Confer EXECUTE on a MemoryObject — the sole kernel source of EXECUTE.
///
/// Requires an `ExecAuthority` cap (with CONFIGURE). Derives a
/// `READ|EXECUTE|GRANT|TRANSFER` capability to the MemoryObject named by
/// `src_mo` into `(dest_cnode, dest_slot)`, as a CDT child of the source cap, so
/// revoking the source cascades. `src_mo` must be a readable MemoryObject; the
/// source cap is never mutated.
pub fn mo_mark_executable(
    exec_authority: CapRef,
    src_mo: CapRef,
    dest_cnode: CapRef,
    dest_slot: u64,
) -> i32 {
    mo_mark_executable_ref(exec_authority, src_mo, dest_cnode, CapRef::flat(dest_slot))
}

pub fn mo_mark_executable_ref(
    exec_authority: CapRef,
    src_mo: CapRef,
    dest_cnode: CapRef,
    dest_slot: CapRef,
) -> i32 {
    write_invoke_depth(src_mo.depth(), dest_slot.depth());
    invoke(
        exec_authority.addr(),
        uapi::KERNITE_INV_MO_MARK_EXECUTABLE as u64,
        src_mo.addr(),
        dest_cnode.addr(),
        dest_slot.addr(),
        0,
    )
    .error as i32
}

/// Populate a freshly-retyped (empty `Anon`) MemoryObject with borrowed device
/// frames, atomically flipping its kind to `BorrowedFrames`.
///
/// The `page_count` pages starting at `device_offset` bytes into `device_ut` (a
/// device Untyped — e.g. the immortal initrd) back the MO one-to-one; the frames
/// are never PMM-owned, freed, or evicted. Requires CONFIGURE on the MO and READ
/// on the device Untyped; the kernel restricts the device Untyped to the initrd.
pub fn mo_populate_borrowed(
    mo: CapRef,
    device_ut: CapRef,
    device_offset: u64,
    page_count: u64,
) -> i32 {
    invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_POPULATE_BORROWED as u64,
        device_ut.addr(),
        device_offset,
        page_count,
        0,
    )
    .error as i32
}

/// Resize a MemoryObject (only works if created with the resizable
/// flag).
pub fn mo_resize(mo: CapRef, new_page_count: u64) -> i32 {
    invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_RESIZE as u64,
        new_page_count,
        0,
        0,
        0,
    )
    .error as i32
}

/// Read bytes from a committed MemoryObject range into the caller
/// IPC buffer.
pub fn mo_read(mo: CapRef, offset: u64, count: u64) -> (i32, u64) {
    let r = invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_READ as u64,
        offset,
        count,
        0,
        0,
    );
    (r.error as i32, r.value)
}

/// Write bytes from the caller IPC buffer into a committed
/// MemoryObject range.
pub fn mo_write(mo: CapRef, offset: u64, count: u64) -> (i32, u64) {
    let r = invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_WRITE as u64,
        offset,
        count,
        0,
        0,
    );
    (r.error as i32, r.value)
}

/// Return whether a page already resolves in this MemoryObject or
/// any COW ancestor.
pub fn mo_has_page(mo: CapRef, page_index: u64) -> (i32, bool) {
    let r = invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_HAS_PAGE as u64,
        page_index,
        0,
        0,
        0,
    );
    (r.error as i32, r.value != 0)
}

/// Return the number of reverse-map entries currently observing
/// this MemoryObject.
pub fn mo_get_map_count(mo: CapRef) -> (i32, u64) {
    let r = invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_GET_MAP_COUNT as u64,
        0,
        0,
        0,
        0,
    );
    (r.error as i32, r.value)
}

/// Update / query the frame flags backing an MO page. Returns the
/// previous flag word.
pub fn mo_update_page_flags(
    mo: CapRef,
    page_index: u64,
    set_flags: u64,
    clear_flags: u64,
) -> (i32, u64) {
    let r = invoke(
        mo.addr(),
        uapi::KERNITE_INV_MO_UPDATE_PAGE_FLAGS as u64,
        page_index,
        set_flags,
        clear_flags,
        0,
    );
    (r.error as i32, r.value)
}

/// Map a range of pages from a MemoryObject into a VSpace.
/// `count_and_flags` encodes `(count << 32) | flags`.
pub fn vspace_map_mo_with_count(
    vspace: CapRef,
    mo_cap: u64,
    vaddr: u64,
    mo_offset: u64,
    count_and_flags: u64,
) -> (i32, u64) {
    let r = invoke(
        vspace.addr(),
        uapi::KERNITE_INV_VSPACE_MAP_MO as u64,
        mo_cap,
        vaddr,
        mo_offset,
        count_and_flags,
    );
    (r.error as i32, r.value)
}

/// Map a range from a MemoryObject as raw demand PTEs while keeping
/// the MO / VmArea metadata registration that the kernel's MO-aware
/// fault paths need.
pub fn vspace_map_mo_demand_with_count(
    vspace: CapRef,
    mo_cap: u64,
    vaddr: u64,
    mo_offset: u64,
    count_and_flags: u64,
) -> (i32, u64) {
    vspace_map_mo_with_count(
        vspace,
        mo_cap,
        vaddr,
        mo_offset,
        count_and_flags | (uapi::KERNITE_VSPACE_MAP_MO_FLAG_DEMAND as u64),
    )
}

pub fn vspace_map_mo(
    vspace: CapRef,
    mo_cap: u64,
    vaddr: u64,
    mo_offset: u64,
    count_and_flags: u64,
) -> i32 {
    vspace_map_mo_with_count(vspace, mo_cap, vaddr, mo_offset, count_and_flags).0
}

pub fn vspace_map_mo_demand(
    vspace: CapRef,
    mo_cap: u64,
    vaddr: u64,
    mo_offset: u64,
    count_and_flags: u64,
) -> i32 {
    vspace_map_mo_demand_with_count(vspace, mo_cap, vaddr, mo_offset, count_and_flags).0
}

// ---------------------------------------------------------------------------
// DeviceControl operations.
// ---------------------------------------------------------------------------

pub fn device_control_create_ioport_depth(
    device_control: CapRef,
    base_port: u64,
    num_ports: u64,
    dest_cspace: CapRef,
    dest_slot: u64,
    dest_depth: u8,
) -> i32 {
    write_invoke_depth(dest_depth, 0);
    invoke(
        device_control.addr(),
        uapi::KERNITE_INV_DEVICE_CONTROL_CREATE_IOPORT as u64,
        base_port,
        num_ports,
        dest_cspace.addr(),
        dest_slot,
    )
    .error as i32
}

pub fn device_control_create_ioport(
    device_control: CapRef,
    base_port: u64,
    num_ports: u64,
    dest_cspace: CapRef,
    dest_slot: u64,
) -> i32 {
    device_control_create_ioport_depth(
        device_control,
        base_port,
        num_ports,
        dest_cspace,
        dest_slot,
        0,
    )
}

pub fn device_control_create_device_untyped_depth(
    device_control: CapRef,
    phys_addr: u64,
    size_bits: u64,
    dest_cspace: CapRef,
    dest_slot: u64,
    dest_depth: u8,
) -> i32 {
    write_invoke_depth(dest_depth, 0);
    invoke(
        device_control.addr(),
        uapi::KERNITE_INV_DEVICE_CONTROL_CREATE_DEVICE_UNTYPED as u64,
        phys_addr,
        size_bits,
        dest_cspace.addr(),
        dest_slot,
    )
    .error as i32
}

pub fn device_control_create_device_untyped(
    device_control: CapRef,
    phys_addr: u64,
    size_bits: u64,
    dest_cspace: CapRef,
    dest_slot: u64,
) -> i32 {
    device_control_create_device_untyped_depth(
        device_control,
        phys_addr,
        size_bits,
        dest_cspace,
        dest_slot,
        0,
    )
}

pub fn device_control_create_irq_handler_depth(
    device_control: CapRef,
    irq: u64,
    dest_cspace: CapRef,
    dest_slot: u64,
    flags: u64,
    dest_depth: u8,
) -> i32 {
    write_invoke_depth(dest_depth, 0);
    invoke(
        device_control.addr(),
        uapi::KERNITE_INV_DEVICE_CONTROL_CREATE_IRQ_HANDLER as u64,
        irq,
        dest_cspace.addr(),
        dest_slot,
        flags,
    )
    .error as i32
}

pub fn device_control_create_irq_handler(
    device_control: CapRef,
    irq: u64,
    dest_cspace: CapRef,
    dest_slot: u64,
    flags: u64,
) -> i32 {
    device_control_create_irq_handler_depth(device_control, irq, dest_cspace, dest_slot, flags, 0)
}

// ---------------------------------------------------------------------------
// Depth-aware helpers for CNode hierarchy (expanded CSpace).
// ---------------------------------------------------------------------------

/// Write per-thread invoke depths for the next depth-aware invoke
/// call. `depth = 0` means flat mode.
fn write_invoke_depth(d0: u8, d1: u8) {
    let _ = invoke(
        uapi::KERNITE_CAP_SELF_TCB as u64,
        uapi::KERNITE_INV_TCB_SET_INVOKE_DEPTHS as u64,
        d0 as u64,
        d1 as u64,
        0,
        0,
    );
}

pub fn cnode_copy_depth(
    src_cnode: CapRef,
    src_slot: u64,
    dest_cnode: CapRef,
    dest_slot: u64,
    rights: u64,
    src_depth: u8,
    dest_depth: u8,
) -> i32 {
    write_invoke_depth(src_depth, dest_depth);
    invoke(
        src_cnode.addr(),
        uapi::KERNITE_INV_CNODE_COPY as u64,
        src_slot,
        dest_cnode.addr(),
        dest_slot,
        rights,
    )
    .error as i32
}

pub fn cnode_copy(
    src_cnode: CapRef,
    src_slot: u64,
    dest_cnode: CapRef,
    dest_slot: u64,
    rights: u64,
) -> i32 {
    cnode_copy_depth(src_cnode, src_slot, dest_cnode, dest_slot, rights, 0, 0)
}

/// Copy a capability naming each endpoint as a depth-carrying [`CapRef`]
/// (slot address + invoke depth) instead of a bare slot plus a separately
/// derived depth. The `*_cnode` arguments still name the CNode objects the
/// slots live in (the same for an intra-CSpace copy, distinct for a
/// cross-CSpace spawn). Callers pass `OwnedCap::borrow()` /
/// `OwnedSlot::borrow()` when a typed handle carries the depth, or resolve a
/// bare slot once at the boundary, so the depth is read off the reference
/// rather than re-derived at every copy site.
pub fn cnode_copy_ref(
    src_cnode: CapRef,
    src: CapRef,
    dest_cnode: CapRef,
    dest: CapRef,
    rights: u64,
) -> i32 {
    cnode_copy_depth(
        src_cnode,
        src.addr(),
        dest_cnode,
        dest.addr(),
        rights,
        src.depth(),
        dest.depth(),
    )
}

pub fn cnode_mint(
    src_cnode: CapRef,
    src_slot: u64,
    dest_cnode: CapRef,
    dest_slot: u64,
    badge: u64,
) -> i32 {
    cnode_mint_depth(src_cnode, src_slot, dest_cnode, dest_slot, badge, 0, 0)
}

/// Mint a capability naming the invoke depth of each slot explicitly. Like
/// [`cnode_copy_depth`], `mint` invokes on the *source* cnode, so the depth
/// pair is `(src_depth, dest_depth)`. `depth = 0` selects flat (root-cspace)
/// resolution.
pub fn cnode_mint_depth(
    src_cnode: CapRef,
    src_slot: u64,
    dest_cnode: CapRef,
    dest_slot: u64,
    badge: u64,
    src_depth: u8,
    dest_depth: u8,
) -> i32 {
    write_invoke_depth(src_depth, dest_depth);
    invoke(
        src_cnode.addr(),
        uapi::KERNITE_INV_CNODE_MINT as u64,
        src_slot,
        dest_cnode.addr(),
        dest_slot,
        badge,
    )
    .error as i32
}

/// Mint a capability naming each endpoint as a depth-carrying [`CapRef`],
/// mirroring [`cnode_copy_ref`].
pub fn cnode_mint_ref(
    src_cnode: CapRef,
    src: CapRef,
    dest_cnode: CapRef,
    dest: CapRef,
    badge: u64,
) -> i32 {
    cnode_mint_depth(
        src_cnode,
        src.addr(),
        dest_cnode,
        dest.addr(),
        badge,
        src.depth(),
        dest.depth(),
    )
}

pub fn cnode_move(dest_cnode: CapRef, dest_slot: u64, src_cnode: CapRef, src_slot: u64) -> i32 {
    cnode_move_depth(dest_cnode, dest_slot, src_cnode, src_slot, 0, 0)
}

/// Move a capability naming the invoke depth of each slot explicitly. `move`
/// invokes on the *destination* cnode, so the depth pair is
/// `(dest_depth, src_depth)` — the inverse of [`cnode_copy_depth`], which
/// invokes on the source. `depth = 0` selects flat (root-cspace) resolution.
pub fn cnode_move_depth(
    dest_cnode: CapRef,
    dest_slot: u64,
    src_cnode: CapRef,
    src_slot: u64,
    dest_depth: u8,
    src_depth: u8,
) -> i32 {
    write_invoke_depth(dest_depth, src_depth);
    invoke(
        dest_cnode.addr(),
        uapi::KERNITE_INV_CNODE_MOVE as u64,
        dest_slot,
        src_cnode.addr(),
        src_slot,
        0,
    )
    .error as i32
}

/// Move a capability naming each endpoint as a depth-carrying [`CapRef`],
/// mirroring [`cnode_copy_ref`]: pass `OwnedCap::borrow()` /
/// `OwnedSlot::borrow()` so the depth rides on the reference instead of being
/// re-derived at the move site.
pub fn cnode_move_ref(dest_cnode: CapRef, dest: CapRef, src_cnode: CapRef, src: CapRef) -> i32 {
    cnode_move_depth(
        dest_cnode,
        dest.addr(),
        src_cnode,
        src.addr(),
        dest.depth(),
        src.depth(),
    )
}

pub fn cnode_mutate(
    dest_cnode: CapRef,
    dest_slot: u64,
    src_cnode: CapRef,
    src_slot: u64,
    badge: u64,
) -> i32 {
    cnode_mutate_depth(dest_cnode, dest_slot, src_cnode, src_slot, badge, 0, 0)
}

/// Mutate a capability naming the invoke depth of each slot explicitly. Like
/// [`cnode_move_depth`], `mutate` invokes on the *destination* cnode, so the
/// depth pair is `(dest_depth, src_depth)`. `depth = 0` selects flat
/// (root-cspace) resolution.
pub fn cnode_mutate_depth(
    dest_cnode: CapRef,
    dest_slot: u64,
    src_cnode: CapRef,
    src_slot: u64,
    badge: u64,
    dest_depth: u8,
    src_depth: u8,
) -> i32 {
    write_invoke_depth(dest_depth, src_depth);
    invoke(
        dest_cnode.addr(),
        uapi::KERNITE_INV_CNODE_MUTATE as u64,
        dest_slot,
        src_cnode.addr(),
        src_slot,
        badge,
    )
    .error as i32
}

/// Mutate a capability naming each endpoint as a depth-carrying [`CapRef`],
/// mirroring [`cnode_move_ref`].
pub fn cnode_mutate_ref(
    dest_cnode: CapRef,
    dest: CapRef,
    src_cnode: CapRef,
    src: CapRef,
    badge: u64,
) -> i32 {
    cnode_mutate_depth(
        dest_cnode,
        dest.addr(),
        src_cnode,
        src.addr(),
        badge,
        dest.depth(),
        src.depth(),
    )
}

pub fn cnode_delete_depth(cnode: CapRef, slot: u64, depth: u8) -> i32 {
    write_invoke_depth(depth, 0);
    invoke(
        cnode.addr(),
        uapi::KERNITE_INV_CNODE_DELETE as u64,
        slot,
        0,
        0,
        0,
    )
    .error as i32
}

pub fn cnode_delete(cnode: CapRef, slot: u64) -> i32 {
    cnode_delete_depth(cnode, slot, 0)
}

pub fn cnode_revoke_depth(cnode: CapRef, slot: u64, depth: u8) -> i32 {
    write_invoke_depth(depth, 0);
    invoke(
        cnode.addr(),
        uapi::KERNITE_INV_CNODE_REVOKE as u64,
        slot,
        0,
        0,
        0,
    )
    .error as i32
}

pub fn cnode_revoke(cnode: CapRef, slot: u64) -> i32 {
    cnode_revoke_depth(cnode, slot, 0)
}

// ---------------------------------------------------------------------------
// EventQueue / Watch / MessagePipe helpers.
// ---------------------------------------------------------------------------

pub fn eq_wait(eq: CapRef, deadline: u64) -> i32 {
    invoke(
        eq.addr(),
        uapi::KERNITE_INV_EQ_WAIT as u64,
        deadline,
        0,
        0,
        0,
    )
    .error as i32
}

pub fn watch_register(watch: CapRef, watched: CapRef, eq: CapRef, mask: u64, cookie: u64) -> i32 {
    invoke(
        watch.addr(),
        uapi::KERNITE_INV_WATCH_REGISTER as u64,
        watched.addr(),
        eq.addr(),
        mask,
        cookie,
    )
    .error as i32
}

pub fn mp_core_pair(core: CapRef, send: CapRef, recv: CapRef) -> i32 {
    invoke(
        core.addr(),
        uapi::KERNITE_INV_MP_CORE_PAIR as u64,
        send.addr(),
        recv.addr(),
        0,
        0,
    )
    .error as i32
}

pub fn dp_core_pair(core: CapRef, producer: CapRef, consumer: CapRef, datagram: bool) -> i32 {
    invoke(
        core.addr(),
        uapi::KERNITE_INV_DP_CORE_PAIR as u64,
        producer.addr(),
        consumer.addr(),
        datagram as u64,
        0,
    )
    .error as i32
}

/// Set a DataPipe side's RX byte threshold (`STATE_READ_THRESHOLD` asserts
/// when inbound `used >= threshold`; `0` disables).
pub fn dp_set_rx_threshold(side: CapRef, threshold: u32) -> i32 {
    invoke(
        side.addr(),
        uapi::KERNITE_INV_DP_SET_RX_THRESHOLD as u64,
        threshold as u64,
        0,
        0,
        0,
    )
    .error as i32
}

/// Set a DataPipe side's TX free-space threshold (`STATE_WRITE_THRESHOLD`
/// asserts when outbound `free >= threshold`; `0` disables).
pub fn dp_set_tx_threshold(side: CapRef, threshold: u32) -> i32 {
    invoke(
        side.addr(),
        uapi::KERNITE_INV_DP_SET_TX_THRESHOLD as u64,
        threshold as u64,
        0,
        0,
        0,
    )
    .error as i32
}

/// Half-close a DataPipe side's write direction: further produce returns
/// `PeerClosed` and the peer reader sees EOF after draining.
pub fn dp_shutdown(side: CapRef) -> i32 {
    invoke(
        side.addr(),
        uapi::KERNITE_INV_DP_SHUTDOWN as u64,
        0,
        0,
        0,
        0,
    )
    .error as i32
}

// `mmsrv_reserve_range / mmsrv_unreserve_range` (mmsrv typed RPC)
// live in `trona_runtime::client::mm` — they ride on `MP_CALL` and
// wear the `MM_RESERVE_RANGE / MM_UNRESERVE_RANGE` protocol labels,
// which are server wire (`trona_protocol::mm`), not kernel ABI.

// ---------------------------------------------------------------------------
// Watch operations.
// ---------------------------------------------------------------------------

/// Cancel a `Watch`.
///
/// Disarms, detaches from the source object's watcher list, bumps the
/// per-watch cancel epoch, and purges any records already queued
/// under this watch's cookie from the bound `EventQueue`. Records
/// that were already drained by `EQ_WAIT` cannot be recalled —
/// userland dispatchers must validate the cookie's `live_gen` field.
/// The kernel side is queue hygiene + teardown determinism, not the
/// truth source for stale-event safety.
pub fn watch_cancel(watch: CapRef) -> i32 {
    invoke(
        watch.addr(),
        uapi::KERNITE_INV_WATCH_CANCEL as u64,
        0,
        0,
        0,
        0,
    )
    .error as i32
}

/// Arm a `Timer` to fire at absolute monotonic `deadline_ns`. `period_ns == 0`
/// is one-shot; `> 0` auto-rearms at `deadline + period` after each fire. On
/// fire the kernel enqueues an `EVENT_TYPE_TIMER` record carrying `cookie` on
/// the bound `EventQueue`.
pub fn timer_set(timer: CapRef, deadline_ns: u64, period_ns: u64, eq: CapRef, cookie: u64) -> i32 {
    invoke(
        timer.addr(),
        uapi::KERNITE_INV_TIMER_SET as u64,
        deadline_ns,
        period_ns,
        eq.addr(),
        cookie,
    )
    .error as i32
}

/// Disarm a `Timer`.
pub fn timer_cancel(timer: CapRef) -> i32 {
    invoke(
        timer.addr(),
        uapi::KERNITE_INV_TIMER_CANCEL as u64,
        0,
        0,
        0,
        0,
    )
    .error as i32
}
