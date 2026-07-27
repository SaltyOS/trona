// SPDX-License-Identifier: GPL-2.0-only
//
//! Lazy resolution of non-bootstrap service caps via `NAMESRV_LOOKUP`.
//!
//! The bootstrap cap_table delivers only the namespace root
//! (`__trona_cap_namesrv_ep`) plus a small set of always-required caps
//! (init control, signal pipe, system caps).
//! Service endpoints (mmsrv / rsrcsrv / vfs / console / netsrv /
//! win32srv) are resolved on first use through this module:
//!
//! 1. The corresponding `caps::*_ep()` getter observes the weak symbol
//!    is still 0 and dispatches to the matching helper here.
//! 2. The helper allocates a fresh receive slot and issues
//!    `NAMESRV_LOOKUP("<service>")` against `caps::namesrv_ep()`.
//!    namesrv mints (or copies — see `BADGE_AS_CALLER`) a per-caller
//!    cap into the receive slot.
//! 3. For services with a per-client request tier (mmsrv, vfs), the
//!    helper additionally issues the service-specific `*_BIND_CLIENT_SELF`
//!    against the resolved master service-EP cap to receive the
//!    per-client request-MP send. Subsequent RPCs flow through that send.
//! 4. The resolved cap is committed into the weak symbol via
//!    `write_volatile`. Concurrent first-use from multiple threads
//!    races at this commit; both threads land on caps that are
//!    siblings in the kernel CDT, so a redundant resolve costs one
//!    extra round-trip but does not corrupt state.
//!
//! `reset_lazy_caps_for_fork` zeroes every weak symbol in this set.
//! Called from `_trona_post_fork_child` so the child re-resolves
//! against its own (fresh) namespace root rather than reading the
//! parent's stale slot indices.

use crate::core::slot_alloc::OwnedCap;
use trona_kernel::core_types::{Cap, TronaMsg};

// Wire constants — matches `userland/core/namesrv/src/wire.rs` and
// `userland/core/mmsrv/src/labels.rs`. Kept inline where the label is
// server-private; VFS uses the public protocol constant because the
// bind is part of its client-facing bootstrap wire.

const NAMESRV_LOOKUP: u64 = 0x210;
const MM_BIND_CLIENT_SELF: u64 = 0x408;
const NAME_PACK_BASE: usize = 1;
const MAX_NAME_BYTES: usize = 64;

/// Resolve a service name through namesrv and write the resulting cap
/// into `weak_target`. Returns the resolved cap, or 0 on failure
/// (namespace root absent, allocator empty, namesrv rejected). The
/// caller is responsible for the `cached == 0 ?` fast path before
/// dispatching here.
///
/// Concurrent first-use race resolution: two threads can race past
/// the `cached == 0 ?` check and both reach this function. Each will
/// issue its own `NAMESRV_LOOKUP` and obtain a *sibling* cap (kernel
/// CDT children of the same namesrv-side source). The thread that
/// observes a non-zero `weak_target` after its own lookup completes
/// drops its sibling via `release_cap` and returns the cap that won
/// the race. Without this cleanup the loser would leak its sibling
/// and the per-process allocator would slowly bleed slots on a hot
/// fork-then-resolve path.
///
/// This is a check-then-set sequence rather than `compare_exchange`
/// because the substrate's weak symbols are `static mut u64` for
/// historical reasons. The race window between the post-resolve
/// `read_volatile` and the subsequent `write_volatile` is small but
/// non-zero — under heavy contention two threads can both write,
/// leaving exactly one cap leaked. That residual is bounded by the
/// number of concurrent first-uses and acceptable until the weak
/// symbols migrate to `AtomicU64`.
pub fn resolve_into(name: &[u8], weak_target: *mut u64) -> Cap {
    let resolved = match name {
        b"mmsrv" => resolve_mmsrv(),
        b"vfs" => resolve_vfs(),
        _ => resolve_simple(name),
    };
    let Some(resolved) = resolved else {
        return 0;
    };
    unsafe {
        let existing = core::ptr::read_volatile(weak_target);
        if existing != 0 {
            // Lost the first-use race: a sibling cap already owns the weak
            // symbol. Drop ours (delete + free) and return the winner.
            drop(resolved);
            return existing;
        }
        // Won the race: leak the cap into the weak symbol — it is now a
        // process-lifetime role cap that no scope releases.
        let slot = resolved.into_raw();
        core::ptr::write_volatile(weak_target, slot);
        slot
    }
}

/// Single-step lookup against namesrv. Used for rsrcsrv /
/// console / win32srv — services that publish their client-facing
/// endpoint through `NAMESRV_REGISTER`, with namesrv minting a
/// per-caller copy on `BADGE_AS_CALLER` lookup.
fn resolve_simple(name: &[u8]) -> Option<OwnedCap> {
    let namesrv_ep = unsafe { core::ptr::read_volatile(&raw const crate::__trona_cap_namesrv_ep) };
    if namesrv_ep == 0 {
        return None;
    }
    let dest = crate::core::slot_alloc::alloc_slot_or_idle(b"lazy_resolve dest");
    let ipc_ctx = current_ipc_ctx();
    if ipc_ctx.is_null() {
        // `dest` (OwnedSlot) drops here → empty slot returned to the pool.
        return None;
    }
    unsafe {
        crate::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx,
            uapi::KERNITE_CAP_SELF_CSPACE as Cap,
            dest.addr(),
            0,
        );
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_LOOKUP;
    let len = pack_name_into_msg(&mut msg, name);
    msg.length = len as u64;

    let mut reply = TronaMsg::zeroed();
    let r = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ipc_ctx,
            namesrv_ep,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if r != 0 || reply.label != uapi::KERNITE_OK as u64 {
        // No cap landed → `dest` drops → empty slot freed.
        return None;
    }
    Some(dest.assume_filled())
}

/// Two-step resolve for mmsrv: lookup the master service-EP, then
/// `MM_BIND_CLIENT_SELF` to obtain the per-client request-MP send. The
/// master cap is freed after the bind completes — only the per-client
/// send is retained.
fn resolve_mmsrv() -> Option<OwnedCap> {
    resolve_bound_service(b"mmsrv", MM_BIND_CLIENT_SELF, b"lazy_resolve mmsrv self")
}

/// Two-step resolve for vfs: lookup the master service-EP, then
/// `VFS_BIND_CLIENT_SELF` to obtain the per-client request-MP send.
fn resolve_vfs() -> Option<OwnedCap> {
    resolve_bound_service(
        b"vfs",
        trona_protocol::vfs::public::VFS_BIND_CLIENT_SELF,
        b"lazy_resolve vfs self",
    )
}

/// Shared two-step resolver for services that publish a bootstrap
/// master endpoint and return the real per-client request send through
/// a bind RPC.
fn resolve_bound_service(name: &[u8], bind_label: u64, alloc_label: &[u8]) -> Option<OwnedCap> {
    let master = resolve_simple(name)?;

    let dest = crate::core::slot_alloc::alloc_slot_or_idle(alloc_label);
    let ipc_ctx = current_ipc_ctx();
    if ipc_ctx.is_null() {
        // `dest` (OwnedSlot) and `master` (OwnedCap) drop here.
        return None;
    }
    unsafe {
        crate::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx,
            uapi::KERNITE_CAP_SELF_CSPACE as Cap,
            dest.addr(),
            0,
        );
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = bind_label;
    msg.length = 0;

    let mut reply = TronaMsg::zeroed();
    let r = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ipc_ctx,
            master.as_raw(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    // The master send is transient — release it now that the bind is issued.
    drop(master);
    if r != 0 || reply.label != uapi::KERNITE_OK as u64 {
        // No per-client send landed → `dest` drops → empty slot freed.
        return None;
    }
    Some(dest.assume_filled())
}

/// Pack `name` into `msg.regs[NAME_PACK_BASE..]` with the byte length
/// at `regs[NAME_PACK_BASE - 1]`. Returns the number of regs occupied
/// by length + bytes.
fn pack_name_into_msg(msg: &mut TronaMsg, name: &[u8]) -> usize {
    let len = name.len().min(MAX_NAME_BYTES);
    msg.regs[NAME_PACK_BASE - 1] = len as u64;
    let mut written = 0;
    let mut word_idx = NAME_PACK_BASE;
    while written < len && word_idx < msg.regs.len() {
        let mut word = [0u8; 8];
        let chunk = (len - written).min(8);
        word[..chunk].copy_from_slice(&name[written..written + chunk]);
        msg.regs[word_idx] = u64::from_le_bytes(word);
        written += chunk;
        word_idx += 1;
    }
    word_idx
}

/// Borrow the current thread's IPC context.
fn current_ipc_ctx() -> *mut trona_kernel::core_types::IpcContext {
    crate::thread::tls::current_ipc_ctx()
}

/// Look up an arbitrary service name through namesrv and return a
/// fresh cap pointing at it.
///
/// Unlike [`resolve_into`] this does not cache the result — every
/// call allocates a new CSpace slot, issues
/// `NAMESRV_LOOKUP("<name>")`, and hands the cap back to the caller.
/// Used by clients that resolve a service ephemerally (vfs's mount
/// handlers, for example, look up the per-mount backend EP and
/// store it directly in `BackendSessionSlot.send_cap` rather than a
/// weak symbol).
///
/// Returns `None` on namespace-root absence or any namesrv-side error
/// (slot exhaustion halts the thread). The returned [`OwnedCap`] owns the
/// resolved cap; dropping it deletes the cap and frees the slot.
pub fn namesrv_lookup_blocking(name: &[u8]) -> Option<OwnedCap> {
    resolve_simple(name)
}

/// Reset every lazy-resolved weak symbol so the next getter call
/// re-resolves through the (post-fork) namespace root. The slot
/// indices written into the symbols by the parent point into the
/// parent's CSpace and are stale in the COW-forked child.
pub fn reset_lazy_caps_for_fork() {
    unsafe {
        core::ptr::write_volatile(&raw mut crate::__trona_cap_rsrcsrv_ep, 0);
        core::ptr::write_volatile(&raw mut crate::__trona_cap_mmsrv_ep, 0);
        core::ptr::write_volatile(&raw mut crate::__trona_cap_vfs_ep, 0);
        core::ptr::write_volatile(&raw mut crate::__trona_cap_ldsrv_ep, 0);
        core::ptr::write_volatile(&raw mut crate::__trona_cap_console_ep, 0);
        core::ptr::write_volatile(&raw mut crate::__trona_cap_win32srv_ep, 0);
    }
}
