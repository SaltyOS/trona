//! POSIX memory management — thin IPC client to mmsrv
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All page allocation (brk/sbrk/mmap/munmap/mprotect) is delegated to the
//! centralized memory server (mmsrv) via IPC.  fd-backed mmap (file, mount,
//! device) uses MM_FILE_MMAP; mmsrv resolves the fd backing via
//! VFS_BACKEND_RESOLVE_BACKING and maps pages directly into the client's VSpace.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::protocol::*;
use trona::types::core::*;

// ---------------------------------------------------------------------------
// brk / sbrk
// ---------------------------------------------------------------------------

/// Set the program break (end of heap) to `addr`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_brk(addr: u64) -> i32 {
    unsafe {
        let mmsrv = trona::caps::mmsrv_ep();
        if mmsrv == 0 {
            return -1;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_BRK;
        msg.length = 1;
        msg.regs[0] = addr;
        let err = crate::ipc_call_retry(
            mmsrv,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK { -1 } else { 0 }
    }
}

/// Increment the program break by `increment` bytes.
/// Returns the previous break address on success, or `u64::MAX` on error.
pub unsafe fn posix_sbrk(increment: i64) -> u64 {
    unsafe {
        let mmsrv = trona::caps::mmsrv_ep();
        if mmsrv == 0 {
            return u64::MAX;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_SBRK;
        msg.length = 1;
        msg.regs[0] = increment as u64;
        let err = crate::ipc_call_retry(
            mmsrv,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            u64::MAX
        } else {
            reply.regs[0]
        }
    }
}

// ---------------------------------------------------------------------------
// mmap / munmap / mprotect
// ---------------------------------------------------------------------------

/// Map pages into the process address space.
///
/// - **Anonymous** (`MAP_ANONYMOUS`): delegates to mmsrv via `MM_MMAP`.
/// - **fd-backed** (`fd >= 0`): delegates to mmsrv via `MM_FILE_MMAP`.
///   mmsrv resolves the fd backing via VFS_BACKEND_RESOLVE_BACKING and maps
///   pages directly into the client's VSpace (file, mount, device).
///
/// Returns the mapped base address, or `MAP_FAILED` (usize::MAX) on error.
pub unsafe fn posix_mmap(
    addr: *mut u8,
    length: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> *mut u8 {
    unsafe {
        let mmsrv = trona::caps::mmsrv_ep();
        if mmsrv == 0 || length == 0 {
            return usize::MAX as *mut u8;
        }

        // fd-backed mmap: delegate to mmsrv
        if fd >= 0 && (flags & MAP_ANONYMOUS) == 0 {
            if offset < 0 {
                return usize::MAX as *mut u8;
            }
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = MM_FILE_MMAP;
            msg.length = 6;
            msg.regs[0] = fd as u64;
            msg.regs[1] = offset as u64;
            msg.regs[2] = length;
            msg.regs[3] = prot as u64;
            msg.regs[4] = flags as u64;
            msg.regs[5] = addr as u64;
            let err = crate::ipc_call_retry(
                mmsrv,
                &raw const msg,
                &raw mut reply,
            );
            if err != 0 || reply.label != TRONA_OK {
                return usize::MAX as *mut u8;
            }
            return reply.regs[0] as *mut u8;
        }

        if (flags & MAP_ANONYMOUS) == 0 {
            return usize::MAX as *mut u8;
        }

        // Anonymous mmap → mmsrv IPC
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MMAP;
        msg.length = 4;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;
        msg.regs[2] = prot as u64;
        msg.regs[3] = flags as u64;
        let err = crate::ipc_call_retry(
            mmsrv,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            usize::MAX as *mut u8
        } else {
            reply.regs[0] as *mut u8
        }
    }
}

/// Materialize a current-process range through mmsrv before first use.
pub unsafe fn posix_prefault(addr: *mut u8, length: u64, prot: i32) -> i32 {
    unsafe {
        let mmsrv = trona::caps::mmsrv_ep();
        if mmsrv == 0 || length == 0 {
            return -1;
        }

        let pid = crate::proc::posix_getpid();
        if pid <= 0 {
            return -1;
        }

        let start = (addr as u64) & !0xFFFu64;
        let end = match (addr as u64).checked_add(length).and_then(|v| v.checked_add(4095)) {
            Some(v) => v & !0xFFFu64,
            None => return -1,
        };
        if end <= start {
            return -1;
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_PREFAULT_RANGE;
        msg.length = 4;
        msg.regs[0] = pid as u64;
        msg.regs[1] = start;
        msg.regs[2] = (end - start) / 4096;
        msg.regs[3] = prot as u64;
        let err = crate::ipc_call_retry(
            mmsrv,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK { -1 } else { 0 }
    }
}

/// Unmap a previously mmap'd region.
/// All regions (anonymous, file-backed, device) are managed by mmsrv.
pub unsafe fn posix_munmap(addr: *mut u8, length: u64) -> i32 {
    unsafe {
        let mmsrv = trona::caps::mmsrv_ep();
        if mmsrv == 0 {
            return -1;
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MUNMAP;
        msg.length = 2;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;
        let err = crate::ipc_call_retry(
            mmsrv,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK { -1 } else { 0 }
    }
}

/// Change protection flags on a mapped region.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_mprotect(addr: *mut u8, length: u64, prot: i32) -> i32 {
    unsafe {
        let mmsrv = trona::caps::mmsrv_ep();
        if mmsrv == 0 {
            return -1;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MPROTECT;
        msg.length = 3;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;
        msg.regs[2] = prot as u64;
        let err = crate::ipc_call_retry(
            mmsrv,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK { -1 } else { 0 }
    }
}
