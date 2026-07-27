// SPDX-License-Identifier: GPL-2.0-only
//! Per-process SHM bulk I/O to VFS.
//!
//! When a read exceeds 4KB, the bulk path is attempted: VFS lazily
//! creates a per-client SHM object, returns a cap copy, and this
//! process maps that cap through its own mmsrv endpoint. Subsequent
//! reads transfer data through the SHM instead of packing bytes into
//! IPC registers per round-trip.

use crate::*;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use trona_kernel::core_types::*;
use trona_protocol::posix_abi::mm::{PROT_READ, PROT_WRITE};
use trona_protocol::vfs::public::{
    VFS_BULK_SHM_REPLY_REG_BYTES, VFS_BULK_SHM_REPLY_REG_COUNT, VFS_BULK_SHM_REPLY_REG_SHM_IDX,
    VFS_BULK_SHM_REPLY_REG_TOKEN, VFS_MOUNT_LIST, VFS_READ, VFS_REGISTER_BULK_SHM,
    VFS_RELEASE_BULK_SHM, VFS_RW_FLAG_SHM, VFS_WRITE,
};

/// Base address of the per-process bulk SHM mapping. 0 = not yet set up.
static BULK_SHM_ADDR: AtomicU64 = AtomicU64::new(0);
static BULK_SHM_BYTES_MAPPED: AtomicU64 = AtomicU64::new(0);
static BULK_SHM_TOKEN: AtomicU64 = AtomicU64::new(0);
static BULK_SHM_CAP_SLOT: AtomicU64 = AtomicU64::new(0);
static BULK_SHM_STATE: AtomicU32 = AtomicU32::new(0);
const BULK_SHM_UNINIT: u32 = 0;
const BULK_SHM_INITING: u32 = 1;
const BULK_SHM_READY: u32 = 2;
const BULK_SHM_REQUEST_BYTES: u64 = 256 * 4096;

#[inline]
fn log_bulk_read_none(reason: &[u8], fd: i32, count: u64, total: u64, err: i32, label: u64) {
    trona_runtime::uerror!(|_lb| {
        _lb.str(b"[POSIXDBG] bulk_read none reason=");
        _lb.str(reason);
        _lb.str(b" fd=");
        if fd < 0 {
            _lb.str(b"-");
            _lb.dec(fd.wrapping_neg() as u64);
        } else {
            _lb.dec(fd as u64);
        }
        _lb.str(b" count=");
        _lb.dec(count);
        _lb.str(b" total=");
        _lb.dec(total);
        if err != 0 {
            _lb.str(b" err=");
            _lb.hex(err as u32 as u64);
        }
        if label != 0 {
            _lb.str(b" label=");
            _lb.hex(label);
        }
        _lb.str(b"\n");
    });
}

#[inline]
fn bulk_shm_state_ptr() -> *const u32 {
    &BULK_SHM_STATE as *const AtomicU32 as *const u32
}

unsafe fn bulk_shm_cap_slot() -> Option<u64> {
    let cached = BULK_SHM_CAP_SLOT.load(Ordering::Acquire);
    if cached != 0 {
        return Some(cached);
    }
    let slot = trona_runtime::core::slot_alloc::alloc_slot()?;
    match BULK_SHM_CAP_SLOT.compare_exchange(0, slot.addr(), Ordering::AcqRel, Ordering::Acquire) {
        // We won the race: the cache owns the slot for the process lifetime;
        // suppress the OwnedSlot Drop so it is not reclaimed while cached.
        Ok(_) => Some(slot.into_raw()),
        // We lost: the OwnedSlot Drop reclaims our now-unused slot.
        Err(existing) => Some(existing),
    }
}

#[inline]
fn finish_bulk_shm_setup(success: bool) -> bool {
    if success {
        BULK_SHM_STATE.store(BULK_SHM_READY, Ordering::Release);
    } else {
        BULK_SHM_STATE.store(BULK_SHM_UNINIT, Ordering::Release);
    }
    let _ = trona_kernel::syscall::futex_wake(bulk_shm_state_ptr(), u32::MAX);
    success
}

/// Lazy one-time SHM setup. Returns true if bulk path is available.
///
/// The setup sequence:
/// 1. Ask VFS to create and map its side of the SHM region.
/// 2. Receive the SHM cap copy in a stable slot.
/// 3. Map the cap into this process via self-tier `MM_SHM_MAP`.
///
/// On any failure, returns false and the caller falls back to the legacy
/// 152-byte-per-IPC read path.
unsafe fn ensure_bulk_shm() -> bool {
    unsafe {
        loop {
            match BULK_SHM_STATE.load(Ordering::Acquire) {
                BULK_SHM_READY => return true,
                BULK_SHM_INITING => {
                    let _ =
                        trona_kernel::syscall::futex_wait(bulk_shm_state_ptr(), BULK_SHM_INITING);
                    continue;
                }
                _ => {}
            }

            if BULK_SHM_STATE
                .compare_exchange(
                    BULK_SHM_UNINIT,
                    BULK_SHM_INITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
        }

        let vfs_ep = trona_runtime::client::caps::vfs_ep();
        if vfs_ep.is_null() {
            return finish_bulk_shm_setup(false);
        }

        if BULK_SHM_ADDR.load(Ordering::Acquire) == 0 {
            let Some(cap_slot) = bulk_shm_cap_slot() else {
                return finish_bulk_shm_setup(false);
            };
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_REGISTER_BULK_SHM;
            msg.regs[0] = BULK_SHM_REQUEST_BYTES;
            msg.length = 1;
            // Save the caller's sticky receive slot, arm ours for the returned
            // SHM cap, then restore. Leaving the receive window armed makes the
            // next IPC Call on this thread fail with INVALID_ARGUMENT.
            let saved_recv =
                trona_kernel::ipc::get_receive_slot_path_ctx(crate::tls::current_ipc_ctx());
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                crate::tls::current_ipc_ctx(),
                uapi::KERNITE_CAP_SELF_CSPACE as u64,
                cap_slot,
                0,
            );
            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                vfs_ep.addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            trona_kernel::ipc::set_receive_slot_path_ctx(
                crate::tls::current_ipc_ctx(),
                saved_recv.0,
                saved_recv.1,
                saved_recv.2,
                saved_recv.3,
            );
            if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
                log_bulk_read_none(b"reg_reply_fail", -1, 0, 0, err, reply.label);
                let _ = trona_kernel::invoke::cnode_delete_depth(
                    CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
                    cap_slot,
                    0,
                );
                return finish_bulk_shm_setup(false);
            }
            if reply.length < VFS_BULK_SHM_REPLY_REG_COUNT {
                let _ = trona_kernel::invoke::cnode_delete_depth(
                    CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
                    cap_slot,
                    0,
                );
                return finish_bulk_shm_setup(false);
            }
            let bytes = reply.regs[VFS_BULK_SHM_REPLY_REG_BYTES];
            let shm_idx = reply.regs[VFS_BULK_SHM_REPLY_REG_SHM_IDX];
            let token = reply.regs[VFS_BULK_SHM_REPLY_REG_TOKEN];
            let mapped = match map_received_bulk_shm(shm_idx, cap_slot, bytes) {
                Some(addr) => addr,
                None => {
                    release_vfs_bulk_shm(token);
                    let _ = trona_kernel::invoke::cnode_delete_depth(
                        CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
                        cap_slot,
                        0,
                    );
                    return finish_bulk_shm_setup(false);
                }
            };
            let _ = trona_kernel::invoke::cnode_delete_depth(
                CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
                cap_slot,
                0,
            );
            BULK_SHM_ADDR.store(mapped, Ordering::Release);
            BULK_SHM_BYTES_MAPPED.store(bytes, Ordering::Release);
            BULK_SHM_TOKEN.store(token, Ordering::Release);
            log_bulk_read_none(b"setup_ok", -1, 0, mapped, 0, 0);
        }

        finish_bulk_shm_setup(true)
    }
}

unsafe fn map_received_bulk_shm(shm_idx: u64, cap_slot: u64, bytes: u64) -> Option<u64> {
    unsafe {
        if bytes == 0 {
            return None;
        }
        let mmsrv = trona_runtime::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return None;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona_protocol::mm::MM_SHM_MAP;
        msg.length = 6;
        msg.regs[0] = 0;
        msg.regs[1] = shm_idx;
        msg.regs[2] = 0;
        msg.regs[3] = bytes;
        msg.regs[4] = (PROT_READ | PROT_WRITE) as u64;
        msg.regs[5] = 0;
        trona_kernel::ipc::set_send_cap_ctx(crate::tls::current_ipc_ctx(), 0, cap_slot);
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[POSIXDBG] shm_map_fail err=");
                _lb.hex(err as u32 as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b" shm_idx=");
                _lb.hex(shm_idx);
                _lb.str(b" bytes=");
                _lb.dec(bytes);
                _lb.str(b"\n");
            });
            None
        } else {
            Some(reply.regs[0])
        }
    }
}

unsafe fn release_vfs_bulk_shm(token: u64) {
    unsafe {
        let vfs_ep = trona_runtime::client::caps::vfs_ep();
        if vfs_ep.is_null() || token == 0 {
            return;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_RELEASE_BULK_SHM;
        msg.length = 1;
        msg.regs[0] = token;
        let _ = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            vfs_ep.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
    }
}

pub(crate) unsafe fn release_bulk_shm() {
    unsafe {
        let addr = BULK_SHM_ADDR.swap(0, Ordering::AcqRel);
        let bytes = BULK_SHM_BYTES_MAPPED.swap(0, Ordering::AcqRel);
        let token = BULK_SHM_TOKEN.swap(0, Ordering::AcqRel);
        BULK_SHM_STATE.store(BULK_SHM_UNINIT, Ordering::Release);
        if addr != 0 && bytes != 0 {
            let _ = trona_runtime::client::mm::munmap(addr as *mut u8, bytes);
        }
        release_vfs_bulk_shm(token);
    }
}

/// Bulk read via SHM. Returns bytes read, or None if not available.
///
/// The caller should attempt this for reads > 4KB. If it returns None,
/// the caller falls back to the legacy 152-byte-per-IPC loop.
pub(crate) unsafe fn bulk_read(fd: i32, buf: *mut u8, count: u64) -> Option<usize> {
    unsafe {
        if !ensure_bulk_shm() {
            log_bulk_read_none(b"ensure_shm", fd, count, 0, 0, 0);
            return None;
        }

        let shm_addr = BULK_SHM_ADDR.load(Ordering::Acquire);
        let shm_size = BULK_SHM_BYTES_MAPPED.load(Ordering::Acquire);
        if shm_addr == 0 || shm_size == 0 {
            log_bulk_read_none(b"no_mapping", fd, count, 0, 0, 0);
            return None;
        }
        let vfs_ep = trona_runtime::client::caps::vfs_ep();
        let mut total = 0u64;

        while total < count {
            let chunk = (count - total).min(shm_size);
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            // Unified VFS_READ wire with the SHM flag: data lands in the
            // per-process bulk SHM region (offset 0), reply carries the count.
            msg.label = VFS_READ;
            msg.regs[0] = fd as u64;
            msg.regs[1] = u64::MAX; // use current file offset
            msg.regs[2] = chunk; // count
            msg.regs[3] = VFS_RW_FLAG_SHM;
            msg.regs[4] = 0; // client_shm_offset
            msg.regs[5] = chunk; // client_shm_len
            msg.length = 6;

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                vfs_ep.addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err == (uapi::KERNITE_ERR_INTERRUPTED as u64) as i32 {
                log_bulk_read_none(b"eintr", fd, count, total, err, reply.label);
                return None; // fall back to legacy path for EINTR handling
            }
            if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
                if total > 0 {
                    return Some(total as usize);
                }
                log_bulk_read_none(b"reply", fd, count, total, err, reply.label);
                return None;
            }

            let got = reply.regs[0];
            if got == 0 {
                break;
            }

            // SAFETY: shm_addr is mapped with got <= shm_size bytes valid.
            // buf is caller-provided with at least count bytes writable.
            ::core::ptr::copy_nonoverlapping(
                shm_addr as *const u8,
                buf.add(total as usize),
                got as usize,
            );
            total += got;
            if got < chunk {
                break; // short read = EOF
            }
        }

        Some(total as usize)
    }
}

/// Bulk pwrite via SHM. Returns bytes written, or None if not available.
pub(crate) unsafe fn bulk_pwrite(
    fd: i32,
    buf: *const u8,
    count: u64,
    offset: u64,
) -> Option<usize> {
    unsafe {
        if !ensure_bulk_shm() {
            return None;
        }

        let shm_addr = BULK_SHM_ADDR.load(Ordering::Acquire);
        let shm_size = BULK_SHM_BYTES_MAPPED.load(Ordering::Acquire);
        if shm_addr == 0 || shm_size == 0 {
            return None;
        }
        let vfs_ep = trona_runtime::client::caps::vfs_ep();
        let mut total = 0u64;

        while total < count {
            let chunk = (count - total).min(shm_size);
            ::core::ptr::copy_nonoverlapping(
                buf.add(total as usize),
                shm_addr as *mut u8,
                chunk as usize,
            );

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            // Unified VFS_WRITE wire with the SHM flag: source bytes live in
            // the per-process bulk SHM region (offset 0); regs[1] is the
            // explicit file offset (pwrite), regs[2] the byte count.
            msg.label = VFS_WRITE;
            msg.regs[0] = fd as u64;
            msg.regs[1] = match offset.checked_add(total) {
                Some(v) => v,
                None => {
                    return if total > 0 {
                        Some(total as usize)
                    } else {
                        None
                    };
                }
            };
            msg.regs[2] = chunk; // count
            msg.regs[3] = VFS_RW_FLAG_SHM;
            msg.regs[4] = 0; // client_shm_offset
            msg.regs[5] = chunk; // client_shm_len
            msg.length = 6;

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                vfs_ep.addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err == (uapi::KERNITE_ERR_INTERRUPTED as u64) as i32 {
                return None; // fall back to legacy path for EINTR handling
            }
            if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
                if total > 0 {
                    return Some(total as usize);
                }
                return None;
            }

            let wrote = reply.regs[0];
            if wrote == 0 {
                break;
            }

            total += wrote;
            if wrote < chunk {
                break;
            }
        }

        Some(total as usize)
    }
}

/// Bulk mount-table snapshot via SHM, backing `posix_mount_list`.
///
/// Returns `(written, available)` where `written` is the number of
/// [`TronaMountInfo`] records placed in `out` and `available` is the
/// total active mount count. When `out` is empty this is a
/// count-only call: no SHM region is touched and `(0, available)` is
/// returned, so a caller can size its buffer before refilling.
/// Returns `None` if the bulk-SHM path is unavailable (no vfs
/// endpoint, registration failed, or the server rejected the call).
pub(crate) unsafe fn bulk_mount_list(out: &mut [TronaMountInfo]) -> Option<(i32, i32)> {
    unsafe {
        let vfs_ep = trona_runtime::client::caps::vfs_ep();
        if vfs_ep.is_null() {
            return None;
        }

        // Count-only: report `available` without a SHM region.
        if out.is_empty() {
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_MOUNT_LIST;
            msg.regs[0] = 0;
            msg.length = 1;
            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                vfs_ep.addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
                return None;
            }
            return Some((0, reply.regs[1] as i32));
        }

        if !ensure_bulk_shm() {
            return None;
        }
        let shm_addr = BULK_SHM_ADDR.load(Ordering::Acquire);
        let shm_size = BULK_SHM_BYTES_MAPPED.load(Ordering::Acquire);
        if shm_addr == 0 || shm_size == 0 {
            return None;
        }

        let rec_bytes = core::mem::size_of::<TronaMountInfo>();
        let region_cap = (shm_size as usize) / rec_bytes;
        let cap = out.len().min(region_cap).min(TRONA_MOUNT_LIST_MAX_ENTRIES);
        if cap == 0 {
            return None;
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_MOUNT_LIST;
        msg.regs[0] = cap as u64;
        msg.length = 1;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            vfs_ep.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
            return None;
        }

        let written = (reply.regs[0] as usize).min(cap);
        let available = reply.regs[1] as i32;
        // SAFETY: the server wrote `written <= cap` records of
        // `rec_bytes` each, packed from SHM offset 0; `cap` is bounded
        // by the mapped region size, and the region is page-aligned so
        // the `TronaMountInfo` (align 8) reads are aligned.
        let src = shm_addr as *const TronaMountInfo;
        for idx in 0..written {
            out[idx] = core::ptr::read(src.add(idx));
        }
        Some((written as i32, available))
    }
}
