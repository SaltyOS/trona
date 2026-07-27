// SPDX-License-Identifier: GPL-2.0-only
//
//! IPC client helpers for the PE-target kernel32.dll.
//!
//! Mirrors substrate's message-pipe helpers but the trap goes through
//! raw kernite invoke labels on a `MessagePipe` peer. PE target cannot
//! link substrate rmeta directly, so the same wire code is recompiled
//! here.

use crate::runtime::current_ipc_ctx;
use crate::syscall::invoke;
use crate::types::{IpcContext, TronaMsg};

/// Infinite-deadline sentinel for `mp_call_ctx` (mirrors the substrate's
/// `IPC_TIMEOUT_BLOCK_FOREVER`; the PE target cannot link substrate rmeta,
/// so the value is recompiled here like the rest of the wire helpers).
pub const IPC_TIMEOUT_BLOCK_FOREVER: u64 = u64::MAX;

/// Pack the message info word for `MP_CALL`. Matches the kernel-side
/// encoding in `kernite/src/syscall/cspace.rs`: low 7 bits = length,
/// next 5 bits = extra-cap count, upper 40 bits = label.
#[inline(always)]
pub fn msginfo(label: u64, length: u64, caps: u64) -> u64 {
    (label << 12) | (caps << 7) | (length & 0x7f)
}

unsafe fn clear_send_caps_ctx(ctx: *mut IpcContext) {
    unsafe {
        if ctx.is_null() {
            return;
        }
        let c = &mut *ctx;
        if !c.ipc_buffer.is_null() {
            for i in 0..4 {
                (*c.ipc_buffer).caps[i] = 0;
            }
        }
        c.send_cap_count = 0;
    }
}

/// Stage `regs[3..length]` into the IPC buffer overflow area at
/// `msg[5..length+2]` (UAPI `regs[]` overlay — `msg[2 + k] =
/// regs[k]`). `regs[0..3]` ride in the `MP_CALL` invoke arg
/// registers. Layout mirrors substrate's `write_overflow_ctx` in
/// `lib/trona/substrate/ipc.rs` exactly so PE callers and saltyos-
/// target callers serialise to the same wire shape.
unsafe fn write_overflow_ctx(ctx: *mut IpcContext, msg: *const TronaMsg) {
    unsafe {
        let len = (*msg).length as usize;
        let len = if len > 32 { 32 } else { len };
        if ctx.is_null() || len <= 3 {
            return;
        }
        let c = &*ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        let n = len - 3;
        for i in 0..n {
            (*c.ipc_buffer).msg[5 + i] = (*msg).regs[3 + i];
        }
    }
}

/// Synchronous client RPC against a `MessagePipe` peer.
pub unsafe fn mp_call_ctx(
    ctx: *mut IpcContext,
    ep: u64,
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
        let active_ctx = if ctx.is_null() {
            current_ipc_ctx()
        } else {
            ctx
        };
        let saved_meta = if active_ctx.is_null() || (*active_ctx).ipc_buffer.is_null() {
            None
        } else {
            Some((
                (*(*active_ctx).ipc_buffer).mp_flags,
                (*(*active_ctx).ipc_buffer).mp_txid,
            ))
        };
        if let Some(_) = saved_meta {
            (*(*active_ctx).ipc_buffer).mp_flags = 0;
            (*(*active_ctx).ipc_buffer).mp_txid = 0;
        }
        let info = msginfo((*msg).label, (*msg).length, caps as u64);
        if !active_ctx.is_null() && !(*active_ctx).ipc_buffer.is_null() {
            let len = ((*msg).length as usize).min(32);
            for i in 0..len {
                (*(*active_ctx).ipc_buffer).msg[2 + i] = (*msg).regs[i];
            }
        }
        let r = invoke(ep, uapi::KERNITE_INV_MP_CALL as u64, info, deadline, 0, 0);
        if caps > 0 && !ctx.is_null() {
            clear_send_caps_ctx(ctx);
        }
        if r.error == 0 && !reply.is_null() {
            if !active_ctx.is_null() && !(*active_ctx).ipc_buffer.is_null() {
                let buf = &*(*active_ctx).ipc_buffer;
                (*reply).label = buf.msg[0];
                (*reply).length = buf.msg[1];
                for i in 0..32 {
                    (*reply).regs[i] = buf.msg[2 + i];
                }
            }
        }
        if let Some((flags, txid)) = saved_meta {
            (*(*active_ctx).ipc_buffer).mp_flags = flags;
            (*(*active_ctx).ipc_buffer).mp_txid = txid;
        }
        r.error as i32
    }
}

/// Blocking send against a `MessagePipe` peer. It does not wait for a
/// reply, so this must be used for one-way protocol records such as
/// `INIT_EXIT`.
pub unsafe fn mp_write_ctx(ctx: *mut IpcContext, ep: u64, msg: *const TronaMsg) -> i32 {
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
        write_overflow_ctx(ctx, msg);
        let r = invoke(
            ep,
            uapi::KERNITE_INV_MP_WRITE as u64,
            info,
            (*msg).regs[0],
            (*msg).regs[1],
            (*msg).regs[2],
        );
        if caps > 0 && !ctx.is_null() {
            clear_send_caps_ctx(ctx);
        }
        if let Some((flags, txid)) = saved_meta {
            (*(*ctx).ipc_buffer).mp_flags = flags;
            (*(*ctx).ipc_buffer).mp_txid = txid;
        }
        r.error as i32
    }
}
