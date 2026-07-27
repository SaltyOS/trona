// SPDX-License-Identifier: GPL-2.0-only
//
//! Thread-spawn supporting helpers — VA region allocator, TLS region
//! init, rollback on partial spawn failure, and the basic
//! cross-thread spinlock used by the loader and other substrate
//! consumers.
//!
//! The historical "worker pool" (`run_workers` + multi-endpoint
//! `recv_any`) is gone. Userspace servers run a single owner reactor
//! on top of [`trona_kernel::ipc`] and the kernite EventQueue + Watch
//! fan-in primitive, so a shared-endpoint worker pool no longer
//! buys anything; spawning a separate request-processing thread is
//! handled by [`crate::thread::thread`] (caller-supplied entry point) and
//! the helpers in this module.
//!
//! Public surface:
//!   * [`SpinLock`] — TTAS spinlock used by `lib/trona/loader/common`
//!     and any substrate consumer that needs cross-thread mutual
//!     exclusion before threads share a higher-level lock primitive.
//!   * [`alloc_worker_va`] — bump-allocate a VA stride for one
//!     spawned thread's stack / IPC buffer / TLS region.
//!   * [`init_worker_tls`] — populate a freshly mapped TLS region
//!     with the static-TLS template plus a [`ThreadLocalBlock`]
//!     anchor.
//!   * [`rollback_worker`] — reverse a partially completed thread
//!     spawn (unmap pages, delete caps, free slots) when a later
//!     stage fails.

use crate::thread::tls::{self, TD_UNUSED, ThreadDesc};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use trona_kernel::core_types::{CapRef, ThreadLocalBlock};
use trona_kernel::invoke;

// ---------------------------------------------------------------------------
// Constants used by alloc_worker_va / rollback_worker
// ---------------------------------------------------------------------------

/// Base VA for spawned-thread regions. Well above userland code/heap
/// to avoid collisions.
const WORKER_REGION_BASE: u64 = 0x0000_0060_0000_0000;

/// Per-thread VA stride: guard + stack + IPC buffer + TLS. 256 KiB
/// allows generous room for TLS growth.
const WORKER_REGION_STRIDE: u64 = 256 * 1024;

/// Well-known capability slots used when unmapping / deleting on
/// rollback.
const CAP_SELF_VSPACE: CapRef = CapRef::flat(1);

// ---------------------------------------------------------------------------
// SpinLock — TTAS mutual exclusion
// ---------------------------------------------------------------------------

/// Test-and-test-and-set spinlock using an `AtomicU32`.
pub struct SpinLock {
    lock: AtomicU32,
}

impl SpinLock {
    pub const fn new() -> Self {
        SpinLock {
            lock: AtomicU32::new(0),
        }
    }

    #[inline]
    pub fn acquire(&self) {
        while self
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.lock.load(Ordering::Relaxed) != 0 {
                ::core::hint::spin_loop();
            }
        }
    }

    #[inline]
    pub fn release(&self) {
        self.lock.store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Worker VA bump allocator
// ---------------------------------------------------------------------------

/// VA bump cursor for spawned-thread regions.
static WORKER_VA_NEXT: AtomicU64 = AtomicU64::new(WORKER_REGION_BASE);

/// Reserve a contiguous VA stride for one spawned thread.
pub(crate) fn alloc_worker_va() -> u64 {
    WORKER_VA_NEXT.fetch_add(WORKER_REGION_STRIDE, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// TLS initialisation for a freshly mapped TLS region
// ---------------------------------------------------------------------------

/// Initialise the TLS region for a spawned thread.
///
/// Returns `(tp_value, tls_block_ptr)` for configuring
/// `tcb_set_tls_base` and the spawned thread's IPC context.
///
/// # Safety
/// `tls_va` must be mapped and writable with at least `tls_size`
/// bytes.
pub(crate) unsafe fn init_worker_tls(
    tls_va: u64,
    tls_size: u64,
    _desc: *mut ThreadDesc,
) -> (u64, *mut ThreadLocalBlock) {
    unsafe {
        let _tls_memsz = tls::static_tls_total_memsz();
        let tls_align = tls::static_tls_align().max(16);
        let tcb_size = ::core::mem::size_of::<ThreadLocalBlock>() as u64;
        let runtime_tcb_align = ::core::mem::align_of::<ThreadLocalBlock>() as u64;

        ::core::ptr::write_bytes(tls_va as *mut u8, 0, tls_size as usize);

        #[cfg(target_arch = "x86_64")]
        let (tp, tls_block) = {
            // Variant II: [ELF TLS data] [ThreadLocalBlock (= TP)]
            let region_end = tls_va + tls_size;
            let tcb_addr = align_down(
                region_end.saturating_sub(tcb_size),
                tls_align.max(runtime_tcb_align),
            );
            let tls_block = tcb_addr as *mut ThreadLocalBlock;
            (tcb_addr, tls_block)
        };

        #[cfg(target_arch = "aarch64")]
        let (tp, tls_block) = {
            // [ABI header (TP)] [ELF TLS data] [ThreadLocalBlock]
            let abi_size = tls::abi_tcb_size();
            let tp = align_down(tls_va, tls_align);
            let tcb_addr = align_up(
                tp.saturating_add(abi_size).saturating_add(_tls_memsz),
                runtime_tcb_align,
            );
            let tls_block = tcb_addr as *mut ThreadLocalBlock;
            (tp, tls_block)
        };

        tls::initialize_static_tls_for_tp(tp);
        tls::install_runtime_tcb_anchor(tp, tls_block);

        (*tls_block).self_ptr = tls_block;

        (tp, tls_block)
    }
}

#[inline]
fn align_down(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value & !(align - 1)
    }
}

#[inline]
#[cfg(target_arch = "aarch64")]
fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.saturating_add(align - 1) & !(align - 1)
    }
}

// ---------------------------------------------------------------------------
// Spawn rollback
// ---------------------------------------------------------------------------

/// Roll back a partially created thread. Unmaps pages, deletes caps,
/// frees the consecutive slot ranges and returns the thread pool
/// descriptor to `TD_UNUSED`.
pub(crate) unsafe fn rollback_worker(desc: *mut ThreadDesc) {
    unsafe {
        if (*desc).mmsrv_backed != 0 {
            if (*desc).stack_base != 0 && (*desc).stack_size != 0 {
                let _ =
                    crate::client::mm::munmap((*desc).stack_base as *mut u8, (*desc).stack_size);
            }
            if (*desc).ipc_buf_vaddr != 0 {
                let _ = crate::client::mm::munmap((*desc).ipc_buf_vaddr as *mut u8, 0x1000);
            }
        } else {
            // Unmap stack
            if (*desc).stack_base != 0 && (*desc).stack_size != 0 {
                let pages = (*desc).stack_size / 0x1000;
                for p in 0..pages {
                    invoke::vspace_unmap(CAP_SELF_VSPACE, (*desc).stack_base + p * 0x1000);
                }
            }
            // Unmap IPC buffer
            if (*desc).ipc_buf_vaddr != 0 {
                invoke::vspace_unmap(CAP_SELF_VSPACE, (*desc).ipc_buf_vaddr);
            }
            // Unmap TLS region
            if (*desc).tls_region != 0 && (*desc).tls_region_size != 0 {
                let pages = (*desc).tls_region_size / 0x1000;
                for p in 0..pages {
                    invoke::vspace_unmap(CAP_SELF_VSPACE, (*desc).tls_region + p * 0x1000);
                }
            }
        }
        // Tear down the worker's owned kernel-object caps. Dropping each owned
        // slot returns it to the allocator only once its CNode entry is known
        // empty; derived caps are preserved by CNode_Delete's CDT re-rooting
        // path. The frame runs free their whole range.
        (*desc).release_caps();

        (*desc).init_tid = 0;
        (*desc).mmsrv_backed = 0;
        (*desc).tls_ptr = core::ptr::null_mut();
        (*desc).stack_base = 0;
        (*desc).stack_size = 0;
        (*desc).tls_region = 0;
        (*desc).tls_region_size = 0;
        (*desc).ipc_buf_vaddr = 0;
        (*desc).state.store(TD_UNUSED, Ordering::Release);
    }
}
