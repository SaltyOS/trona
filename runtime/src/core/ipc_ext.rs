// SPDX-License-Identifier: GPL-2.0-only
//
//! Convenience helpers around `trona_kernel::ipc` that consult the
//! runtime slot allocator. Live here (not in `trona_kernel`) so the
//! kernel ABI wrapper crate stays free of process-runtime state.

use crate::core::slot_alloc;
use trona_kernel::core_types::{Cap, IpcContext};
use trona_kernel::ipc;

/// Configure a receive slot for incoming capability transfers.
///
/// When receiving into the process's own expanded CSpace,
/// automatically use the observed slot-path depth for high slot
/// addresses so cap delivery can target allocator-managed expansion
/// segments as well as the flat root CNode.
///
/// Convenience wrapper around
/// [`trona_kernel::ipc::set_receive_slot_path_ctx`] — fills the
/// `slot_depth` parameter from the runtime slot allocator's current
/// view of `index`.
///
/// # Safety
///
/// `ctx` must be a valid, initialised IPC context. `cnode` is
/// resolved with `depth == 0` against the caller's CSpace
/// (typically `KERNITE_CAP_SELF_CSPACE`).
pub unsafe fn set_receive_slot_ctx(ctx: *mut IpcContext, cnode: Cap, index: u64, depth: u64) {
    let slot_depth = if cnode == uapi::KERNITE_CAP_SELF_CSPACE as u64 && depth == 0 {
        slot_alloc::slot_invoke_depth(index) as u64
    } else {
        0
    };
    unsafe { ipc::set_receive_slot_path_ctx(ctx, cnode, index, depth, slot_depth) }
}

/// Reserve and arm a sticky receive slot for server loops that may
/// receive payload caps while using `mp_read_ctx` followed by
/// `mp_write_reply_read_ctx`.
pub fn arm_mp_write_reply_read_slot_ctx(ctx: *mut IpcContext, tag: &'static [u8]) -> Cap {
    let slot = slot_alloc::slot_alloc_or_idle(tag);
    unsafe {
        set_receive_slot_ctx(ctx, uapi::KERNITE_CAP_SELF_CSPACE as Cap, slot, 0);
    }
    slot
}
