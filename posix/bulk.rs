// SPDX-License-Identifier: GPL-2.0-only
//! Per-process SHM bulk I/O to VFS.
//!
//! When a read exceeds 4KB, the bulk path is attempted: a 256KB shared memory
//! region is lazily created, mapped into both the calling process and VFS,
//! and subsequent reads transfer data through the SHM instead of packing
//! 152 bytes into IPC registers per round-trip.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

/// Base address of the per-process bulk SHM mapping. 0 = not yet set up.
static BULK_SHM_ADDR: AtomicU64 = AtomicU64::new(0);
static BULK_SHM_STATE: AtomicU32 = AtomicU32::new(0);
const BULK_SHM_UNINIT: u32 = 0;
const BULK_SHM_INITING: u32 = 1;
const BULK_SHM_READY: u32 = 2;

#[inline]
fn bulk_shm_state_ptr() -> *const u32 {
    &BULK_SHM_STATE as *const AtomicU32 as *const u32
}

#[inline]
fn finish_bulk_shm_setup(success: bool) -> bool {
    if success {
        BULK_SHM_STATE.store(BULK_SHM_READY, Ordering::Release);
    } else {
        BULK_SHM_STATE.store(BULK_SHM_UNINIT, Ordering::Release);
    }
    let _ = trona::syscall::futex_wake(bulk_shm_state_ptr(), u32::MAX);
    success
}

/// Lazy one-time SHM setup. Returns true if bulk path is available.
///
/// The setup sequence:
/// 1. Create a SHM region via mmsrv (MM_SHM_CREATE)
/// 2. Map it into our own address space (MM_SHM_MAP)
/// 3. Tell VFS to map the same region (VFS_BULK_SETUP)
///
/// On any failure, returns false and the caller falls back to the legacy
/// 152-byte-per-IPC read path.
unsafe fn ensure_bulk_shm() -> bool {
    unsafe {
        loop {
            match BULK_SHM_STATE.load(Ordering::Acquire) {
                BULK_SHM_READY => return true,
                BULK_SHM_INITING => {
                    let _ = trona::syscall::futex_wait(bulk_shm_state_ptr(), BULK_SHM_INITING);
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

        let vfs_ep = trona::caps::vfs_ep();
        let mmsrv_ep = trona::caps::mmsrv_ep();
        if vfs_ep == 0 || mmsrv_ep == 0 {
            return finish_bulk_shm_setup(false);
        }

        // Use badge-derived SHM ID (unique per process)
        let shm_id = super::proc::posix_getpid() as u64 | 0x42_0000_0000;

        if BULK_SHM_ADDR.load(Ordering::Acquire) == 0 {
            // 1. Create SHM via mmsrv
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = MM_SHM_CREATE;
            msg.regs[0] = shm_id;
            msg.regs[1] = BULK_SHM_PAGES;
            msg.length = 2;
            crate::ipc_call_retry(mmsrv_ep, &raw const msg, &raw mut reply);
            if reply.label != TRONA_OK && reply.label != TRONA_ALREADY_EXISTS {
                return finish_bulk_shm_setup(false);
            }

            // 2. Map into our address space exactly once. If later VFS setup
            // fails, retries reuse the same local mapping instead of leaking
            // new auto-placed SHM mappings on each attempt.
            msg = TronaMsg::zeroed();
            reply = TronaMsg::zeroed();
            msg.label = MM_SHM_MAP;
            msg.regs[0] = shm_id;
            msg.regs[1] = 0; // self
            msg.regs[2] = 0; // auto-place
            msg.regs[3] = 0x3; // RW
            msg.length = 4;
            crate::ipc_call_retry(mmsrv_ep, &raw const msg, &raw mut reply);
            if reply.label != TRONA_OK {
                return finish_bulk_shm_setup(false);
            }
            BULK_SHM_ADDR.store(reply.regs[0], Ordering::Release);
        }

        // 3. Tell VFS to map our SHM
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_BULK_SETUP;
        msg.regs[0] = shm_id;
        msg.regs[1] = BULK_SHM_PAGES;
        msg.length = 2;
        crate::ipc_call_retry(vfs_ep, &raw const msg, &raw mut reply);
        if reply.label != TRONA_OK {
            return finish_bulk_shm_setup(false);
        }

        finish_bulk_shm_setup(true)
    }
}

/// Bulk read via SHM. Returns bytes read, or None if not available.
///
/// The caller should attempt this for reads > 4KB. If it returns None,
/// the caller falls back to the legacy 152-byte-per-IPC loop.
pub(crate) unsafe fn bulk_read(fd: i32, buf: *mut u8, count: u64) -> Option<usize> {
    unsafe {
        if !ensure_bulk_shm() {
            return None;
        }

        let shm_addr = BULK_SHM_ADDR.load(Ordering::Acquire);
        let shm_size = BULK_SHM_PAGES * 4096;
        let vfs_ep = trona::caps::vfs_ep();
        let mut total = 0u64;

        while total < count {
            let chunk = (count - total).min(shm_size);
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_BULK_READ;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;
            msg.regs[2] = 0; // shm_offset
            msg.length = 3;

            let err = crate::ipc_call_retry(vfs_ep, &raw const msg, &raw mut reply);
            if err == TRONA_INTERRUPTED as i32 {
                return None; // fall back to legacy path for EINTR handling
            }
            if err != 0 || reply.label != TRONA_OK {
                if total > 0 {
                    return Some(total as usize);
                }
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
pub(crate) unsafe fn bulk_pwrite(fd: i32, buf: *const u8, count: u64, offset: u64) -> Option<usize> {
    unsafe {
        if !ensure_bulk_shm() {
            return None;
        }

        let shm_addr = BULK_SHM_ADDR.load(Ordering::Acquire);
        let shm_size = BULK_SHM_PAGES * 4096;
        let vfs_ep = trona::caps::vfs_ep();
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
            msg.label = VFS_BULK_PWRITE;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;
            msg.regs[2] = match offset.checked_add(total) {
                Some(v) => v,
                None => return if total > 0 { Some(total as usize) } else { None },
            };
            msg.regs[3] = 0; // shm_offset
            msg.length = 4;

            let err = crate::ipc_call_retry(vfs_ep, &raw const msg, &raw mut reply);
            if err == TRONA_INTERRUPTED as i32 {
                return None; // fall back to legacy path for EINTR handling
            }
            if err != 0 || reply.label != TRONA_OK {
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
