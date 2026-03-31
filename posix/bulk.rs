// SPDX-License-Identifier: GPL-2.0-only
//! Per-process SHM bulk I/O to VFS.
//!
//! When a read exceeds 4KB, the bulk path is attempted: a 256KB shared memory
//! region is lazily created, mapped into both the calling process and VFS,
//! and subsequent reads transfer data through the SHM instead of packing
//! 152 bytes into IPC registers per round-trip.

use trona::consts::*;
use trona::ipc;
use trona::types::*;

/// Base address of the per-process bulk SHM mapping. 0 = not yet set up.
static mut BULK_SHM_ADDR: u64 = 0;

/// Whether the bulk SHM has been successfully set up.
static mut BULK_SHM_READY: bool = false;

/// Lazy one-time SHM setup. Returns true if bulk path is available.
///
/// The setup sequence:
/// 1. Create a SHM region via mmsrv (MM_SHM_CREATE)
/// 2. Map it into our own address space (MM_SHM_MAP)
/// 3. Tell VFS to map the same region (POSIX_VFS_BULK_SETUP)
///
/// On any failure, returns false and the caller falls back to the legacy
/// 152-byte-per-IPC read path.
unsafe fn ensure_bulk_shm() -> bool {
    unsafe {
        if *(&raw const BULK_SHM_READY) {
            return true;
        }

        let vfs_ep = super::CAP_VFS_EP;
        let mmsrv_ep = crate::mm::mmsrv_ep();
        if vfs_ep == 0 || mmsrv_ep == 0 {
            return false;
        }

        // Use badge-derived SHM ID (unique per process)
        let shm_id = super::proc::posix_getpid() as u64 | 0x42_0000_0000;

        // 1. Create SHM via mmsrv
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_SHM_CREATE;
        msg.regs[0] = shm_id;
        msg.regs[1] = BULK_SHM_PAGES;
        msg.length = 2;
        crate::ipc_call_retry(mmsrv_ep, &raw const msg, &raw mut reply);
        if reply.label != TRONA_OK && reply.label != TRONA_ALREADY_EXISTS {
            return false;
        }

        // 2. Map into our address space
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
            return false;
        }
        *(&raw mut BULK_SHM_ADDR) = reply.regs[0];

        // 3. Tell VFS to map our SHM
        msg = TronaMsg::zeroed();
        reply = TronaMsg::zeroed();
        msg.label = POSIX_VFS_BULK_SETUP;
        msg.regs[0] = shm_id;
        msg.regs[1] = BULK_SHM_PAGES;
        msg.length = 2;
        crate::ipc_call_retry(vfs_ep, &raw const msg, &raw mut reply);
        if reply.label != TRONA_OK {
            // Non-fatal: fall back to legacy reads
            return false;
        }

        *(&raw mut BULK_SHM_READY) = true;
        true
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

        let shm_addr = *(&raw const BULK_SHM_ADDR);
        let shm_size = BULK_SHM_PAGES * 4096;
        let ctx = crate::tls::current_ipc_ctx();
        let vfs_ep = super::CAP_VFS_EP;
        let mut total = 0u64;

        while total < count {
            let chunk = (count - total).min(shm_size);
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = POSIX_VFS_BULK_READ;
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
            core::ptr::copy_nonoverlapping(
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

        let shm_addr = *(&raw const BULK_SHM_ADDR);
        let shm_size = BULK_SHM_PAGES * 4096;
        let ctx = crate::tls::current_ipc_ctx();
        let vfs_ep = super::CAP_VFS_EP;
        let mut total = 0u64;

        while total < count {
            let chunk = (count - total).min(shm_size);
            core::ptr::copy_nonoverlapping(
                buf.add(total as usize),
                shm_addr as *mut u8,
                chunk as usize,
            );

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = POSIX_VFS_BULK_PWRITE;
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
