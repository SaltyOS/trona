// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-process runtime globals + bootstrap entry for kernel32.dll.
//!
//! These globals carry the kernel-mapped IPC buffer pointer, the
//! send-cap counter, bootstrap endpoints, and a small cap-slot allocator
//! for lazy service lookup. The PE rtld
//! (`ldtrona-pe.so`) calls `kernel32_runtime_init` once during process
//! bringup with the cap slot numbers and allocator range it resolved
//! from the trona startup block.

use crate::types::{IpcContext, TronaMsg};
use core::sync::atomic::{AtomicU64, Ordering};

const NAME_PACK_BASE: usize = 1;
const MAX_NAME_BYTES: usize = 64;
const IPC_RESERVED_RECEIVE_SLOT_DEPTH: usize = 0;

#[unsafe(no_mangle)]
pub static mut __trona_ipc_ctx: IpcContext = IpcContext::new();

#[unsafe(no_mangle)]
pub static mut __win32srv_ep: u64 = 0;

#[unsafe(no_mangle)]
pub static mut __trona_cap_init_ep: u64 = 0;

#[unsafe(no_mangle)]
pub static mut __trona_cap_namesrv_ep: u64 = 0;

#[unsafe(no_mangle)]
pub static mut __trona_cap_vfs_ep: u64 = 0;

static CAP_SLOT_NEXT: AtomicU64 = AtomicU64::new(0);
static CAP_SLOT_LIMIT: AtomicU64 = AtomicU64::new(0);

pub fn current_ipc_ctx() -> *mut IpcContext {
    &raw mut __trona_ipc_ctx
}

pub mod caps {
    use super::{__trona_cap_init_ep, __trona_cap_vfs_ep};

    pub fn init_ep() -> u64 {
        unsafe { *(&raw const __trona_cap_init_ep) }
    }

    pub fn vfs_ep() -> u64 {
        let cached = unsafe { core::ptr::read_volatile(&raw const __trona_cap_vfs_ep) };
        if cached != 0 {
            return cached;
        }
        super::resolve_into(b"vfs", &raw mut __trona_cap_vfs_ep)
    }
}

fn alloc_cap_slot() -> u64 {
    let limit = CAP_SLOT_LIMIT.load(Ordering::Acquire);
    CAP_SLOT_NEXT
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            (next < limit).then_some(next + 1)
        })
        .unwrap_or(0)
}

fn release_cap_slot(slot: u64) {
    let _ = crate::syscall::invoke(
        uapi::KERNITE_CAP_SELF_CSPACE as u64,
        uapi::KERNITE_INV_CNODE_DELETE as u64,
        slot,
        0,
        0,
        0,
    );

    let mut next = CAP_SLOT_NEXT.load(Ordering::Acquire);
    while next == slot + 1 {
        match CAP_SLOT_NEXT.compare_exchange(next, slot, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(observed) => next = observed,
        }
    }
}

fn resolve_into(name: &[u8], cache_slot: *mut u64) -> u64 {
    let resolved = resolve_simple(name);
    if resolved == 0 {
        return 0;
    }
    unsafe {
        let existing = core::ptr::read_volatile(cache_slot);
        if existing != 0 {
            release_cap_slot(resolved);
            return existing;
        }
        core::ptr::write_volatile(cache_slot, resolved);
    }
    resolved
}

fn resolve_simple(name: &[u8]) -> u64 {
    let namesrv_ep = unsafe { core::ptr::read_volatile(&raw const __trona_cap_namesrv_ep) };
    if namesrv_ep == 0 {
        return 0;
    }

    let dest = alloc_cap_slot();
    if dest == 0 {
        return 0;
    }

    let ipc_ctx = current_ipc_ctx();
    if ipc_ctx.is_null() {
        release_cap_slot(dest);
        return 0;
    }

    unsafe {
        set_receive_slot(ipc_ctx, dest);
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = trona_protocol::namesrv::NAMESRV_LOOKUP;
    msg.length = pack_name_into_msg(&mut msg, name) as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        crate::ipc::mp_call_ctx(
            ipc_ctx,
            namesrv_ep,
            &raw const msg,
            &raw mut reply,
            crate::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 || reply.label != uapi::KERNITE_OK as u64 {
        release_cap_slot(dest);
        return 0;
    }

    dest
}

unsafe fn set_receive_slot(ctx: *mut IpcContext, slot: u64) {
    unsafe {
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            return;
        }
        (*(*ctx).ipc_buffer).receive_cnode = uapi::KERNITE_CAP_SELF_CSPACE as u64;
        (*(*ctx).ipc_buffer).receive_index = slot;
        (*(*ctx).ipc_buffer).receive_depth = 0;
        (*(*ctx).ipc_buffer).reserved[IPC_RESERVED_RECEIVE_SLOT_DEPTH] = 0;
    }
}

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

#[unsafe(no_mangle)]
pub extern "C" fn kernel32_runtime_init(
    ipc_buffer_vaddr: u64,
    win32srv_ep: u64,
    cap_init_ep: u64,
    cap_namesrv_ep: u64,
    cap_alloc_base: u64,
    cap_alloc_limit: u64,
) {
    unsafe {
        let ctx = &raw mut __trona_ipc_ctx;
        (*ctx).ipc_buffer = ipc_buffer_vaddr as *mut uapi::kernite_ipc_buffer;
        (*ctx).send_cap_count = 0;
        *(&raw mut __win32srv_ep) = win32srv_ep;
        *(&raw mut __trona_cap_init_ep) = cap_init_ep;
        *(&raw mut __trona_cap_namesrv_ep) = cap_namesrv_ep;
        *(&raw mut __trona_cap_vfs_ep) = 0;
        if cap_alloc_base < cap_alloc_limit {
            CAP_SLOT_NEXT.store(cap_alloc_base, Ordering::Release);
            CAP_SLOT_LIMIT.store(cap_alloc_limit, Ordering::Release);
        } else {
            CAP_SLOT_NEXT.store(0, Ordering::Release);
            CAP_SLOT_LIMIT.store(0, Ordering::Release);
        }
        crate::handle::reset_handle_table();
        crate::console::reset_console_modes();
        crate::error::SetLastError(crate::error::ERROR_SUCCESS);
    }
}
