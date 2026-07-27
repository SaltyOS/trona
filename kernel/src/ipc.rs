// SPDX-License-Identifier: GPL-2.0-only
//
//! MessagePipe IPC primitives.
//!
//! MessagePipe data flow uses `MP_WRITE` (send a record), `MP_READ`
//! (consume one), and `MP_CALL` (send a request, then wait for a
//! reply on the same pipe). Servers receive requests with `MP_READ`
//! and answer calls with reply-marked `MP_WRITE` records.
//! Notifications, timed receives, and multi-source waits are gone —
//! the new event plane (EventQueue + Watch + Timer) composes those
//! explicitly outside this module.
//!
//! # Wire layout
//!
//! `KERNITE_SYS_INVOKE` carries six payload words. For pipe ops:
//!
//! - `cap_ptr` = MessagePipe cap.
//! - `invoke_label` = `KERNITE_INV_MP_*`.
//! - `msg_info_word` packs `(label, length, extra_caps)` —
//!   bits[6:0]=length (0..32), bits[11:7]=extra_caps (0..4),
//!   bits[51:12]=label.
//! - For `MP_WRITE` / `MP_CALL`, the next three words
//!   (`mr0`/`mr1`/`mr2`) carry `regs[0..3)`
//!   directly. `regs[3..length]` overflows through the IPC buffer at
//!   `msg[5..]`.
//! - Replies are `MP_WRITE` records with `ipc_buffer.mp_flags`
//!   carrying `KERNITE_MP_FLAG_REPLY` and `ipc_buffer.mp_txid`
//!   carrying the transaction id copied from the inbound call.
//!
//! # Capability transfer
//!
//! Stage caps via [`set_send_cap_ctx`] before the send; the IPC
//! buffer's `caps[0..4]` array carries source-CSpace slot addresses
//! and the kernel mints them into hidden carriers under `CAP_LOCK`
//! at `MP_WRITE` time. Receivers configure the install target via
//! [`set_receive_slot_ctx`] and read back the installed slots in
//! their own `caps[]` after `MP_READ`.

use crate::core_types::{Cap, IPC_BUFFER_RECV_SLOT_DEPTH_INDEX, IpcContext, TronaMsg};
use crate::syscall::invoke;

const MP_MSG_REGS: usize = 32;
const IPC_BUFFER_MSG_REGS_BASE: usize = 2;
pub const IPC_TIMEOUT_BLOCK_FOREVER: u64 = u64::MAX;
const MP_FLAG_REPLY: u64 = uapi::KERNITE_MP_FLAG_REPLY as u64;

/// Encode `(label, length, extra_caps)` into the msg_info word.
///
/// Layout: bits[6:0]=length, bits[11:7]=extra_caps, bits[51:12]=label.
#[inline(always)]
pub fn msginfo(label: u64, length: u64, caps: u64) -> u64 {
    (label << 12) | ((caps & 0x1F) << 7) | (length & 0x7F)
}

/// Extract the label field from a msg_info word.
#[inline(always)]
pub fn msginfo_label(info: u64) -> u64 {
    (info >> 12) & 0xFF_FFFF_FFFF
}

/// Extract the message length from a msg_info word.
#[inline(always)]
pub fn msginfo_length(info: u64) -> u64 {
    info & 0x7F
}

/// Extract the extra_caps count from a msg_info word.
#[inline(always)]
pub fn msginfo_extracaps(info: u64) -> u64 {
    (info >> 7) & 0x1F
}

/// Initialize an IPC context with the given IPC buffer page address.
///
/// # Safety
/// `ctx` must be a valid pointer. `ipc_buffer_vaddr` must point to a
/// mapped IPC buffer page (or be null to defer initialization).
pub unsafe fn ipc_context_init(
    ctx: *mut IpcContext,
    ipc_buffer_vaddr: *mut uapi::kernite_ipc_buffer,
) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        (*ctx).ipc_buffer = ipc_buffer_vaddr;
        (*ctx).send_cap_count = 0;
    }
}

/// Clear all staged send capabilities and reset `send_cap_count` to
/// `0`.
///
/// This touches only the send-cap staging state (`caps[]` and
/// `send_cap_count`). It deliberately does NOT clear `mp_flags` /
/// `mp_txid`: those carry the reply-routing metadata of the most
/// recently *read* inbound record, and a server that calls this during
/// post-reply cap cleanup (after `mp_write_reply_read_ctx` has already
/// read the next request into the buffer) would otherwise erase that
/// request's txid and reply with txid 0 — which never matches the parked
/// caller's txid, hanging it. Use [`clear_mp_metadata_ctx`] for the separate
/// concern of resetting reply/transaction metadata.
pub unsafe fn clear_send_caps_ctx(ctx: *mut IpcContext) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let c = &mut *ctx;
        if !c.ipc_buffer.is_null() {
            for i in 0..uapi::KERNITE_IPC_MAX_CAPS as usize {
                (*c.ipc_buffer).caps[i] = 0;
            }
        }
        c.send_cap_count = 0;
    }
}

/// Reset the IPC buffer's reply-routing metadata (`mp_flags` /
/// `mp_txid`) to zero.
///
/// Separate from [`clear_send_caps_ctx`] because the two address
/// different state: send-cap staging versus the transaction metadata
/// of the last inbound/outbound record. Call this only at true reset
/// points (e.g. thread/fork reinit) where no in-flight reply depends on
/// the buffer's current txid. The `mp_*` send paths
/// (`mp_call_ctx`, `mp_write_with_metadata_ctx`) set these fields
/// explicitly before every transmit, so ordinary cleanup sites do not
/// need to call this.
pub unsafe fn clear_mp_metadata_ctx(ctx: *mut IpcContext) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let c = &mut *ctx;
        if !c.ipc_buffer.is_null() {
            (*c.ipc_buffer).mp_flags = 0;
            (*c.ipc_buffer).mp_txid = 0;
        }
    }
}

/// Stage a capability for transfer on the next send. `slot_index`
/// (0..`KERNITE_IPC_MAX_CAPS`) selects the position in
/// `ipc_buffer.caps[]`.
pub unsafe fn set_send_cap_ctx(ctx: *mut IpcContext, slot_index: i32, cap_slot: u64) {
    let max = uapi::KERNITE_IPC_MAX_CAPS as i32;
    if ctx.is_null() || slot_index < 0 || slot_index >= max {
        return;
    }
    unsafe {
        let c = &mut *ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        (*c.ipc_buffer).caps[slot_index as usize] = cap_slot;
        if c.send_cap_count < slot_index + 1 {
            c.send_cap_count = slot_index + 1;
        }
    }
}

/// Configure the receive destination for incoming capability
/// transfers. `depth` resolves `cnode` in the caller's CSpace.
/// `slot_depth` resolves the receive slot address rooted at that
/// CNode; pass 0 for flat `cnode[index]`.
///
/// This is the raw form. Process runtime
/// (`trona_runtime::core::ipc_ext::set_receive_slot_ctx`) provides a
/// convenience wrapper that consults the slot allocator to fill
/// `slot_depth` for self-CSpace receives.
pub unsafe fn set_receive_slot_path_ctx(
    ctx: *mut IpcContext,
    cnode: Cap,
    index: u64,
    depth: u64,
    slot_depth: u64,
) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let c = &mut *ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        (*c.ipc_buffer).receive_cnode = cnode;
        (*c.ipc_buffer).receive_index = index;
        (*c.ipc_buffer).receive_depth = depth;
        (*c.ipc_buffer).reserved[IPC_BUFFER_RECV_SLOT_DEPTH_INDEX] = slot_depth;
    }
}

/// Read back the receive-slot configuration currently programmed into the IPC
/// buffer (the values last written by [`set_receive_slot_path_ctx`]). Returns
/// `(cnode, index, depth, slot_depth)`, all zero when no IPC buffer is
/// attached. Pair with `set_receive_slot_path_ctx` to save and restore the
/// receive slot around a one-off capability-receiving call so a server
/// reactor's sticky receive slot is left untouched.
///
/// # Safety
/// `ctx` must be a valid, initialised IPC context.
pub unsafe fn get_receive_slot_path_ctx(ctx: *mut IpcContext) -> (Cap, u64, u64, u64) {
    if ctx.is_null() {
        return (0, 0, 0, 0);
    }
    unsafe {
        let c = &mut *ctx;
        if c.ipc_buffer.is_null() {
            return (0, 0, 0, 0);
        }
        (
            (*c.ipc_buffer).receive_cnode,
            (*c.ipc_buffer).receive_index,
            (*c.ipc_buffer).receive_depth,
            (*c.ipc_buffer).reserved[IPC_BUFFER_RECV_SLOT_DEPTH_INDEX],
        )
    }
}

/// Stage `regs[3..length]` into the IPC buffer's overflow area at
/// `msg[IPC_BUFFER_MSG_REGS_BASE + 3 .. IPC_BUFFER_MSG_REGS_BASE +
/// length]` (UAPI `regs[]` overlay). `regs[0..3]` ride in the
/// `MP_CALL` invoke arg registers (`mr0..mr2` on the kernel side).
unsafe fn write_overflow_ctx(ctx: *mut IpcContext, msg: *const TronaMsg) {
    unsafe {
        let len = (*msg).length as usize;
        let len = if len > MP_MSG_REGS { MP_MSG_REGS } else { len };
        if ctx.is_null() || len <= 3 {
            return;
        }
        let c = &*ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        let n = len - 3;
        for i in 0..n {
            (*c.ipc_buffer).msg[IPC_BUFFER_MSG_REGS_BASE + 3 + i] = (*msg).regs[3 + i];
        }
    }
}

/// Write the FULL request body (`regs[0..length]`) into the IPC buffer's
/// `msg[]` area for `MP_CALL`, whose payload travels in the buffer (not
/// invoke registers) so the `deadline` can ride a register.
unsafe fn write_call_request_ctx(ctx: *mut IpcContext, msg: *const TronaMsg) {
    unsafe {
        let len = (*msg).length as usize;
        let len = if len > MP_MSG_REGS { MP_MSG_REGS } else { len };
        if ctx.is_null() {
            return;
        }
        let c = &*ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        for i in 0..len {
            (*c.ipc_buffer).msg[IPC_BUFFER_MSG_REGS_BASE + i] = (*msg).regs[i];
        }
    }
}

/// Drain the inbound `kernite_mp_record` from the IPC buffer's
/// `msg[]` area into a [`TronaMsg`].
unsafe fn read_inbound_ctx(ctx: *mut IpcContext, msg: *mut TronaMsg) {
    if msg.is_null() || ctx.is_null() {
        return;
    }
    unsafe {
        let c = &*ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        let buf = &*c.ipc_buffer;
        (*msg).label = buf.msg[0];
        (*msg).length = buf.msg[1];
        // Only `length` registers were transferred for this message. The
        // per-thread `ipc_buffer` is reused across receives and the kernel
        // leaves registers beyond `length` holding the previous message's
        // tail, so copy only the valid prefix and zero the rest. This makes
        // "`regs[length..]` reads as 0" a hard invariant for every inbound
        // message — a handler that reads a fixed register index without
        // consulting `length` can never observe a prior message's data.
        let n = ((*msg).length as usize).min(MP_MSG_REGS);
        for i in 0..n {
            (*msg).regs[i] = buf.msg[IPC_BUFFER_MSG_REGS_BASE + i];
        }
        for i in n..MP_MSG_REGS {
            (*msg).regs[i] = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// MessagePipe operations.
// ---------------------------------------------------------------------------

unsafe fn mp_write_with_metadata_ctx(
    ctx: *mut IpcContext,
    mp: Cap,
    msg: *const TronaMsg,
    flags: u64,
    txid: u64,
) -> i32 {
    unsafe {
        let caps = if ctx.is_null() {
            0
        } else {
            (*ctx).send_cap_count
        };
        let saved_meta = if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            None
        } else {
            Some(((*(*ctx).ipc_buffer).mp_flags, (*(*ctx).ipc_buffer).mp_txid))
        };
        if let Some(_) = saved_meta {
            (*(*ctx).ipc_buffer).mp_flags = flags;
            (*(*ctx).ipc_buffer).mp_txid = txid;
        }
        let info = msginfo((*msg).label, (*msg).length, caps as u64);
        write_overflow_ctx(ctx, msg);
        let r = invoke(
            mp,
            uapi::KERNITE_INV_MP_WRITE as u64,
            info,
            (*msg).regs[0],
            (*msg).regs[1],
            (*msg).regs[2],
        );
        if caps > 0 && !ctx.is_null() {
            clear_send_caps_ctx(ctx);
        }
        if let Some((saved_flags, saved_txid)) = saved_meta {
            (*(*ctx).ipc_buffer).mp_flags = saved_flags;
            (*(*ctx).ipc_buffer).mp_txid = saved_txid;
        }
        r.error as i32
    }
}

/// Blocking send on a MessagePipe. Blocks until a receiver consumes
/// the record or the peer closes. Transfers `msg` and any staged
/// capabilities. Returns 0 on success, otherwise a `KERNITE_ERR_*`
/// code.
pub unsafe fn mp_write_ctx(ctx: *mut IpcContext, mp: Cap, msg: *const TronaMsg) -> i32 {
    unsafe { mp_write_with_metadata_ctx(ctx, mp, msg, 0, 0) }
}

/// Non-blocking request send carrying an explicit low-range correlation
/// `txid` (top bit clear) that the server echoes on its reply. Unlike
/// `mp_call_ctx`, the caller does NOT park for the reply: it reads the
/// reply later off the same pipe (e.g. an EventQueue Watch on
/// `STATE_READABLE`) and correlates by `txid`. The kernel rejects
/// user-forged high-range (reserved for sync `MP_CALL`) txids.
pub unsafe fn mp_write_request_ctx(
    ctx: *mut IpcContext,
    mp: Cap,
    msg: *const TronaMsg,
    txid: u64,
) -> i32 {
    unsafe { mp_write_with_metadata_ctx(ctx, mp, msg, 0, txid) }
}

/// Blocking receive on a MessagePipe. Blocks until a record
/// arrives. On success, copies the inbound record into `*msg` and
/// the sender's badge into `*badge`. Returns 0 on success.
pub unsafe fn mp_read_ctx(
    ctx: *mut IpcContext,
    mp: Cap,
    msg: *mut TronaMsg,
    badge: *mut u64,
) -> i32 {
    let r = invoke(mp, uapi::KERNITE_INV_MP_READ as u64, 0, 0, 0, 0);
    if r.error == 0 {
        unsafe {
            if !badge.is_null() && !ctx.is_null() && !(*ctx).ipc_buffer.is_null() {
                *badge = (*(*ctx).ipc_buffer).badge;
            }
            read_inbound_ctx(ctx, msg);
        }
    }
    r.error as i32
}

/// Blocking call on a MessagePipe. The kernel sends the request and
/// waits for a reply record from the same pipe. Servers answer with a
/// reply-marked `MP_WRITE`; no caller-supplied reply object
/// participates in this regular RPC path. On success the reply
/// record is written to `*reply`.
pub unsafe fn mp_call_ctx(
    ctx: *mut IpcContext,
    mp: Cap,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    deadline: u64,
) -> i32 {
    unsafe {
        let caps = if ctx.is_null() {
            0
        } else {
            (*ctx).send_cap_count
        };
        let saved_meta = if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            None
        } else {
            Some(((*(*ctx).ipc_buffer).mp_flags, (*(*ctx).ipc_buffer).mp_txid))
        };
        if let Some(_) = saved_meta {
            (*(*ctx).ipc_buffer).mp_flags = 0;
            (*(*ctx).ipc_buffer).mp_txid = 0;
        }
        let info = msginfo((*msg).label, (*msg).length, caps as u64);
        // The full request body travels in the IPC buffer so the
        // `deadline` can ride invoke register a3 (a4/a5 unused).
        write_call_request_ctx(ctx, msg);
        let r = invoke(mp, uapi::KERNITE_INV_MP_CALL as u64, info, deadline, 0, 0);
        if caps > 0 && !ctx.is_null() {
            clear_send_caps_ctx(ctx);
        }
        if r.error == 0 {
            read_inbound_ctx(ctx, reply);
        }
        if let Some((saved_flags, saved_txid)) = saved_meta {
            (*(*ctx).ipc_buffer).mp_flags = saved_flags;
            (*(*ctx).ipc_buffer).mp_txid = saved_txid;
        }
        r.error as i32
    }
}

/// `mp_call_ctx` plus inline cap staging — convenience for callers that
/// want to send N caps with a single function call instead of
/// staging each via `set_send_cap_ctx` first. The caps are taken
/// from the slice `caps[0..caps_count]` (sender CSpace indices) and
/// staged into `ipc_buffer.caps[]` before dispatching the
/// `KERNITE_INV_MP_CALL`.
pub unsafe fn mp_call_with_caps_ctx(
    ctx: *mut IpcContext,
    mp: Cap,
    msg: *const TronaMsg,
    caps: *const Cap,
    caps_count: u64,
    reply: *mut TronaMsg,
    deadline: u64,
) -> i32 {
    unsafe {
        let max = uapi::KERNITE_IPC_MAX_CAPS as u64;
        let n = if caps_count > max { max } else { caps_count };
        for i in 0..n {
            let c = *caps.add(i as usize);
            set_send_cap_ctx(ctx, i as i32, c);
        }
        mp_call_ctx(ctx, mp, msg, reply, deadline)
    }
}

/// Send a reply record on a MessagePipe using a reply-marked
/// `MP_WRITE` and an explicit `MP_CALL` transaction id.
pub unsafe fn mp_write_reply_to_ctx(
    ctx: *mut IpcContext,
    mp: Cap,
    txid: u64,
    reply: *const TronaMsg,
) -> i32 {
    unsafe {
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
        }
        mp_write_with_metadata_ctx(ctx, mp, reply, MP_FLAG_REPLY, txid)
    }
}

/// Reply immediately to the last record read into `ctx`'s IPC buffer.
pub unsafe fn mp_write_reply_ctx(ctx: *mut IpcContext, mp: Cap, reply: *const TronaMsg) -> i32 {
    unsafe {
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
        }
        let txid = (*(*ctx).ipc_buffer).mp_txid;
        mp_write_reply_to_ctx(ctx, mp, txid, reply)
    }
}

/// Server loop step: write a reply, then receive the next
/// inbound record on `mp`. Both phases share the same MessagePipe.
/// Returns 0 on success.
pub unsafe fn mp_write_reply_read_ctx(
    ctx: *mut IpcContext,
    mp: Cap,
    reply: *const TronaMsg,
    out_msg: *mut TronaMsg,
    badge: *mut u64,
) -> i32 {
    unsafe {
        let reply_err = mp_write_reply_ctx(ctx, mp, reply);
        if reply_err != 0 {
            return reply_err;
        }
    }
    unsafe { mp_read_ctx(ctx, mp, out_msg, badge) }
}
