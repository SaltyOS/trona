//! POSIX memory management — thin IPC client to mmsrv
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All page allocation (brk/sbrk/mmap/munmap/mprotect) is delegated to the
//! centralized memory server (mmsrv) via IPC.  fd-backed mmap (file, mount,
//! device) uses MM_FILE_MMAP; mmsrv resolves the fd backing via
//! VFS_BACKEND_RESOLVE_BACKING and maps pages directly into the client's VSpace.

use crate::*;
// posix consts already in scope via lib.rs `pub use crate::consts::*`
use trona_kernel::core_types::*;
use trona_protocol::posix::*;

fn log_mmap_failure(
    stage: &'static [u8],
    fd: i32,
    length: u64,
    prot: i32,
    flags: i32,
    offset: i64,
    label: u64,
    err: i32,
) {
    let _ = (stage, fd, length, prot, flags, offset, label, err);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[POSIX] mmap failed op=posix_mmap stage=");
        _lb.bytes(stage);
        _lb.str(b" fd=");
        _lb.hex(fd as u64);
        _lb.str(b" len=");
        _lb.hex(length);
        _lb.str(b" prot=");
        _lb.hex(prot as u64);
        _lb.str(b" flags=");
        _lb.hex(flags as u64);
        _lb.str(b" offset=");
        _lb.hex(offset as u64);
        _lb.str(b" label=");
        _lb.hex(label);
        _lb.str(b" err=");
        _lb.hex(err as u64);
        _lb.str(b"\n");
    });
}

// ---------------------------------------------------------------------------
// brk / sbrk
// ---------------------------------------------------------------------------

/// Set the program break (end of heap) to `addr`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_brk(addr: u64) -> i32 {
    if unsafe { trona_runtime::client::mm::brk(addr) }.is_ok() {
        0
    } else {
        -1
    }
}

/// Increment the program break by `increment` bytes.
/// Returns the previous break address on success, or `u64::MAX` on error.
pub unsafe fn posix_sbrk(increment: i64) -> u64 {
    unsafe { trona_runtime::client::mm::sbrk(increment).unwrap_or(u64::MAX) }
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
    match unsafe { trona_runtime::client::mm::mmap(addr, length, prot, flags, fd, offset) } {
        Ok(mapped) => mapped,
        Err(label) => {
            log_mmap_failure(b"substrate", fd, length, prot, flags, offset, label, 0);
            usize::MAX as *mut u8
        }
    }
}

/// Materialize a current-process range through mmsrv before first use.
pub unsafe fn posix_prefault(addr: *mut u8, length: u64, prot: i32) -> i32 {
    unsafe {
        let mmsrv = trona_runtime::client::caps::mmsrv_ep().addr();
        if mmsrv == 0 || length == 0 {
            return -1;
        }

        let start = (addr as u64) & !0xFFFu64;
        let end = match (addr as u64)
            .checked_add(length)
            .and_then(|v| v.checked_add(4095))
        {
            Some(v) => v & !0xFFFu64,
            None => return -1,
        };
        if end <= start {
            return -1;
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_PREFAULT_RANGE;
        msg.length = 3;
        msg.regs[0] = start;
        msg.regs[1] = end - start;
        msg.regs[2] = prot as u64;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            mmsrv,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
            -1
        } else {
            0
        }
    }
}

/// Unmap a previously mmap'd region.
/// All regions (anonymous, file-backed, device) are managed by mmsrv.
pub unsafe fn posix_munmap(addr: *mut u8, length: u64) -> i32 {
    if unsafe { trona_runtime::client::mm::munmap(addr, length) }.is_ok() {
        0
    } else {
        -1
    }
}

/// Synchronize a mapped range.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_msync(addr: *mut u8, length: u64, flags: i32) -> i32 {
    match unsafe { trona_runtime::client::mm::msync(addr, length, flags) } {
        Ok(()) => 0,
        Err(label) => crate::trona_err_to_posix(label),
    }
}

/// Change protection flags on a mapped region.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_mprotect(addr: *mut u8, length: u64, prot: i32) -> i32 {
    if unsafe { trona_runtime::client::mm::mprotect(addr, length, prot) }.is_ok() {
        0
    } else {
        -1
    }
}
