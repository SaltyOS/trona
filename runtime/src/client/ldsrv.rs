// SPDX-License-Identifier: GPL-2.0-only
//! Code-loading authority (`ldsrv`) client surface.
//!
//! The dynamic linker resolves a `DT_NEEDED` shared library by soname
//! ([`resolve_library`]) or a program main image it has already opened through
//! the VFS under its own credential ([`resolve_main`]). Either returns a
//! `READ|EXECUTE` code MemoryObject the linker maps — attenuating per run — into
//! an image envelope. The kernel's cap-derived ceiling is the W^X boundary; the
//! header summary in [`ResolvedImage`] is advisory (the consumer reads the real
//! headers from the code MO).

use crate::core::slot_alloc::{OwnedCap, TransferCap};
use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;
use trona_protocol::ldsrv::{
    LDSRV_RESOLVE_LIBRARY, LDSRV_RESOLVE_MAIN, LDSRV_RESOLVE_MAIN_REQ_REG_OFFSET,
    LDSRV_RESOLVE_MAIN_REQ_REG_SIZE, LDSRV_RESOLVE_REPLY_REG_ENTRY, LDSRV_RESOLVE_REPLY_REG_FORMAT,
    LDSRV_RESOLVE_REPLY_REG_IDENTITY, LDSRV_RESOLVE_REPLY_REG_MO_SIZE,
    LDSRV_RESOLVE_REPLY_REG_PHNUM, LDSRV_RESOLVE_REPLY_REG_PHOFF, LDSRV_RESOLVE_REQ_NAME_BASE,
    LDSRV_RESOLVE_REQ_REG_NAME_LEN,
};

pub type Result<T> = core::result::Result<T, u64>;

/// A code object resolved from `ldsrv`: the `READ|EXECUTE|GRANT|TRANSFER` code
/// MO plus its advisory header summary. The consumer owns `code_mo` — it mints
/// rights-attenuated per-run aliases from it (text `R-X`, rodata `R--`, data
/// COW `R-W`) and drops it once the image is mapped. `format` is
/// `LDSRV_FORMAT_ELF` / `_PE`; `entry` / `phoff` / `phnum` are advisory (zero
/// for a freshly conferred VFS object — read the headers from the MO).
pub struct ResolvedImage {
    pub code_mo: OwnedCap,
    pub mo_size: u64,
    pub identity: u64,
    pub format: u64,
    pub entry: u64,
    pub phoff: u64,
    pub phnum: u64,
}

#[inline]
fn call_error(err: i32) -> u64 {
    err as u64
}

/// Pack `name` bytes contiguously into `regs` starting at word `base`, matching
/// `ldsrv`'s byte-contiguous `copy_name` read of the request register block.
fn pack_name(regs: &mut [u64; 32], base: usize, name: &[u8]) {
    let dst = &raw mut regs[base] as *mut u8;
    let max = (regs.len() - base) * 8;
    let n = name.len().min(max);
    for i in 0..n {
        // SAFETY: `dst` points at `regs[base]`; `n <= max` keeps the write inside
        // the register array, which is a contiguous `[u64; 32]`.
        unsafe { *dst.add(i) = name[i] };
    }
}

/// Number of request words the packed name occupies after the length word.
fn name_words(len: usize) -> u64 {
    len.div_ceil(8) as u64
}

/// Send `msg` to `ldsrv` (optionally staging `send_cap` as `caps[0]`), receive
/// the returned code MO into a fresh slot, and build a [`ResolvedImage`].
///
/// The send-cap window is cleared first so a prior call's staged cap cannot leak
/// into this one (`set_send_cap_ctx` does not auto-reset the count).
///
/// # Safety
/// `ldsrv_addr` names the resolve service endpoint; `msg` is a fully-built
/// request. `send_cap`, if present, is consumed by the send.
unsafe fn call_resolve(
    ldsrv_addr: u64,
    msg: &TronaMsg,
    send_cap: Option<TransferCap>,
) -> Result<ResolvedImage> {
    let ctx = crate::current_ipc_ctx();
    unsafe { trona_kernel::ipc::clear_send_caps_ctx(ctx) };
    if let Some(ref tc) = send_cap {
        unsafe { trona_kernel::ipc::set_send_cap_ctx(ctx, 0, tc.slot()) };
    }

    let Some(slot) = crate::core::slot_alloc::alloc_slot() else {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as u64);
    };

    // Arm a fresh receive slot for the returned code MO, preserving whatever
    // receive-slot configuration was in effect (e.g. a server reactor's sticky
    // slot, if the linker runs inside one).
    let saved = unsafe { trona_kernel::ipc::get_receive_slot_path_ctx(ctx) };
    unsafe {
        crate::core::ipc_ext::set_receive_slot_ctx(
            ctx,
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            slot.addr(),
            0,
        );
    }
    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            ldsrv_addr,
            msg as *const TronaMsg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    unsafe {
        trona_kernel::ipc::set_receive_slot_path_ctx(ctx, saved.0, saved.1, saved.2, saved.3);
    }
    // The slot may now hold the returned code MO; assume_filled so a failure
    // path deletes the delivered cap (and an empty slot is freed).
    let code_mo = unsafe { slot.assume_filled() };
    // The send cap (if any) was moved into ldsrv by the request; drop the
    // transfer handle to reclaim its now-empty slot.
    drop(send_cap);

    if err != 0 {
        return Err(call_error(err));
    }
    if reply.label != TRONA_OK {
        return Err(reply.label);
    }
    Ok(ResolvedImage {
        code_mo,
        mo_size: reply.regs[LDSRV_RESOLVE_REPLY_REG_MO_SIZE],
        identity: reply.regs[LDSRV_RESOLVE_REPLY_REG_IDENTITY],
        format: reply.regs[LDSRV_RESOLVE_REPLY_REG_FORMAT],
        entry: reply.regs[LDSRV_RESOLVE_REPLY_REG_ENTRY],
        phoff: reply.regs[LDSRV_RESOLVE_REPLY_REG_PHOFF],
        phnum: reply.regs[LDSRV_RESOLVE_REPLY_REG_PHNUM],
    })
}

/// Resolve a `DT_NEEDED` shared library by `soname` through an explicit
/// `ldsrv` endpoint. `ldsrv` owns the search order; the reply carries the
/// `READ|EXECUTE` code MO and its summary.
///
/// This is the IPC body factored out of [`resolve_library`] for callers that
/// already hold the endpoint (init's `ldsrv_client_ep`, cached on first use
/// from namesrv) and must NOT go through the runtime weak-symbol
/// `ldsrv_ep()` path — `init` never receives `ROLE_LDSRV_CLIENT` via its
/// cap-table, so that lazy resolve is permanently dead for it. Normal
/// processes keep using [`resolve_library`].
///
/// # Safety
/// `ldsrv_ep` names a valid `ldsrv` service endpoint. Issues an IPC; the
/// caller must hold the cap.
pub unsafe fn resolve_library_at(ldsrv_ep: u64, soname: &[u8]) -> Result<ResolvedImage> {
    if ldsrv_ep == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = LDSRV_RESOLVE_LIBRARY;
    msg.regs[LDSRV_RESOLVE_REQ_REG_NAME_LEN] = soname.len() as u64;
    pack_name(&mut msg.regs, LDSRV_RESOLVE_REQ_NAME_BASE, soname);
    msg.length = LDSRV_RESOLVE_REQ_NAME_BASE as u64 + name_words(soname.len());
    unsafe { call_resolve(ldsrv_ep, &msg, None) }
}

/// Resolve a `DT_NEEDED` shared library by `soname`. `ldsrv` owns the search
/// order; the reply carries the `READ|EXECUTE` code MO and its summary.
///
/// Routes through the runtime weak-symbol `ldsrv_ep()` (lazy-resolved on first
/// call against namesrv). Processes that need a non-lazy endpoint — notably
/// PID 1, which spawns `ldsrv` and never gets `ROLE_LDSRV_CLIENT` from its
/// cap-table — use [`resolve_library_at`] directly with their own cached
/// endpoint.
///
/// # Safety
/// Issues an IPC to ldsrv; the process must hold `ROLE_LDSRV_CLIENT` (or an
/// equivalent bootstrap cap).
pub unsafe fn resolve_library(soname: &[u8]) -> Result<ResolvedImage> {
    let ldsrv = crate::client::caps::ldsrv_ep();
    if ldsrv.is_null() {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
    }
    unsafe { resolve_library_at(ldsrv.addr(), soname) }
}

/// Resolve a program main image the caller has already opened through the VFS
/// under its own credential. `control_ep` is the dedicated exec-control MP
/// (init's private ldsrv channel — `RESOLVE_MAIN` is refused on the public
/// resolve endpoint, so conferring EXECUTE on a caller-supplied backing is
/// gated to that channel's holder). `backing` is the non-exec backing cap from
/// `VFS_OPEN_FOR_EXEC` (consumed by the send); `size` is the exact image byte
/// size and `offset` the image's byte offset within the backing MO. `ldsrv`
/// confers `EXECUTE` and returns the code MO; it never re-opens by path (which
/// would bypass the caller's `X_OK` / `MNT_NOEXEC` check).
///
/// # Safety
/// Issues an IPC to ldsrv over `control_ep`; `backing` must be a transferable
/// non-exec backing MO cap.
pub unsafe fn resolve_main(
    control_ep: u64,
    backing: TransferCap,
    size: u64,
    offset: u64,
) -> Result<ResolvedImage> {
    if control_ep == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = LDSRV_RESOLVE_MAIN;
    msg.regs[LDSRV_RESOLVE_MAIN_REQ_REG_SIZE] = size;
    msg.regs[LDSRV_RESOLVE_MAIN_REQ_REG_OFFSET] = offset;
    msg.length = 2;
    unsafe { call_resolve(control_ep, &msg, Some(backing)) }
}
