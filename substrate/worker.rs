//! Worker pool for multi-threaded IPC services.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides a personality-neutral worker thread pool where N threads all
//! recv on the same endpoint set. The kernel dispatches messages to available
//! workers (FIFO wake). Each worker handles one request at a time.
//!
//! # Usage
//!
//! ```rust,ignore
//! unsafe {
//!     worker::run_workers(&WorkerConfig {
//!         worker_count: 4,
//!         endpoints: (&MY_EP) as *const _,
//!         endpoint_count: 1,
//!         untyped: MY_UT,
//!         self_tcb: CAP_SELF_TCB,
//!         self_sc: SC_CAP,
//!         stack_pages: 16,
//!         pool_budget_us: 0,
//!         pool_period_us: 0,
//!         cspace_depth: 0,
//!     }, my_handler);
//!     // never returns — main thread becomes worker #0
//! }
//! ```
//!
//! # Worker threads
//!
//! Workers are first-class threads in the substrate thread pool with full
//! TLS (IPC context, thread_id, errno). They use `ThreadOwner::Worker`.
//!
//! The handler receives pointers to the incoming message, badge, recv source,
//! and a reply buffer. It fills the reply buffer and returns a
//! [`WorkerLoopControl`] describing whether the loop should send a reply,
//! skip the reply and receive the next request, or exit this worker.
//!
//! Worker #0 (the main thread) must never return `false` — if it does, the
//! process enters an infinite yield loop. Non-main workers that return
//! `false` are reaped via CAS (TD_EXITED -> TD_REAPING).

use crate::consts::*;
use crate::invoke;
use crate::ipc;
use crate::slot_alloc;
use crate::syscall::syscall;
use crate::tls::{self, ThreadDesc, ThreadOwner, TD_EXITED, TD_REAPING, TD_RUNNING, TD_UNUSED};
use crate::types::core::{
    Cap, IpcBuffer, IpcContext, ThreadLocalBlock, TronaMsg, IPC_BUFFER_RESERVED_WORDS,
};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum worker threads (including main thread as worker #0).
const MAX_WORKERS: usize = 32;
/// Maximum shared receive endpoints staged into the IPC buffer.
const MAX_WORKER_ENDPOINTS: usize = IPC_BUFFER_RESERVED_WORDS;

/// Default worker stack size: 16 pages (64 KiB).
const DEFAULT_STACK_PAGES: u64 = 16;

/// Base VA for worker memory regions.
/// Well above userland code/heap to avoid collisions.
const WORKER_REGION_BASE: u64 = 0x0000_0060_0000_0000;

/// Per-worker VA stride: guard + stack + IPC + TLS.
/// 256 KiB allows generous room for TLS growth.
const WORKER_REGION_STRIDE: u64 = 256 * 1024;

/// Well-known capability slots.
const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;

/// Kernel SC tick granularity is 1 ms (budget_us/1000 must be >= 1).
const MIN_BUDGET_US: u64 = 1000;

/// Default scheduling period (100 ms).
const DEFAULT_PERIOD_US: u64 = 100_000;

// ---------------------------------------------------------------------------
// SpinLock
// ---------------------------------------------------------------------------

/// Test-and-test-and-set spinlock using an AtomicU32.
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
// WorkerHandler
// ---------------------------------------------------------------------------

/// Handler function type for worker IPC loops.
///
/// Called with `(ctx, msg, badge, reply)`.
/// - `ctx`: the worker's IPC context (for staging caps, etc.)
/// - `msg`: incoming message (read)
/// - `badge`: sender badge
/// - `reply`: reply buffer to fill
///
pub enum WorkerLoopControl {
    Reply,
    SkipReply,
    Exit,
}

/// Returns a [`WorkerLoopControl`] indicating how the worker loop should
/// handle the post-dispatch receive.
pub type WorkerHandler = unsafe fn(
    ctx: *mut IpcContext,
    msg: *mut TronaMsg,
    badge: u64,
    recv_source: u64,
    reply: *mut TronaMsg,
) -> WorkerLoopControl;

pub type WorkerEnterHook = unsafe fn(ctx: *mut IpcContext, worker_idx: usize);
pub type WorkerTimeoutHook = unsafe fn(ctx: *mut IpcContext, worker_idx: usize);
pub type WorkerTimeoutNsHook = unsafe fn(ctx: *mut IpcContext, worker_idx: usize) -> u64;

// ---------------------------------------------------------------------------
// WorkerConfig
// ---------------------------------------------------------------------------

/// Configuration for spawning a worker pool.
pub struct WorkerConfig {
    /// Number of worker threads (including main thread as worker #0).
    /// Clamped to 1..MAX_WORKERS.
    pub worker_count: usize,
    /// Shared receive endpoints to stage for recv_any/reply_recv_any.
    pub endpoints: *const Cap,
    /// Number of endpoints in `endpoints`.
    pub endpoint_count: usize,
    /// Untyped capability to retype kernel objects from.
    pub untyped: Cap,
    /// Caller's own TCB cap (slot 0 typically).
    pub self_tcb: Cap,
    /// Caller's own SchedContext cap (from __trona_sc_cap or auxv).
    pub self_sc: Cap,
    /// Stack pages per worker (0 = default 16).
    pub stack_pages: u64,
    /// Total scheduling budget for the pool (microseconds). 0 = auto-split.
    /// Each worker gets pool_budget_us / worker_count. The kernel rounds
    /// budget to ms ticks (budget_us/1000 >= 1), so minimum is 1000 us.
    pub pool_budget_us: u64,
    /// Scheduling period (microseconds). 0 = default 100 ms.
    pub pool_period_us: u64,
    /// CNode guard depth for tcb_set_space_with_depth. 0 = use default
    /// tcb_set_space (no explicit depth).
    pub cspace_depth: u64,
    /// Optional hook called on each worker before the first receive.
    pub on_enter: Option<WorkerEnterHook>,
    /// Optional timeout computation hook. Returning 0 blocks indefinitely.
    pub next_timeout_ns: Option<WorkerTimeoutNsHook>,
    /// Optional hook called after a timed receive/reply_recv returns timeout.
    pub on_timeout: Option<WorkerTimeoutHook>,
}

// ---------------------------------------------------------------------------
// Per-worker tracking (maps worker index -> thread pool index)
// ---------------------------------------------------------------------------

struct WorkerSlot {
    /// Thread pool index from `tls::alloc_thread_desc()`, or 0 for worker #0.
    thread_pool_idx: usize,
    /// True if this worker slot is in use.
    active: bool,
}

impl WorkerSlot {
    const fn zeroed() -> Self {
        WorkerSlot {
            thread_pool_idx: 0,
            active: false,
        }
    }
}

static mut WORKER_SLOTS: [WorkerSlot; MAX_WORKERS] = [const { WorkerSlot::zeroed() }; MAX_WORKERS];

/// Shared config snapshot (set once by run_workers, read by all workers).
static mut WORKER_CFG: WorkerCfgSnapshot = WorkerCfgSnapshot::zeroed();

struct WorkerCfgSnapshot {
    endpoints: [Cap; MAX_WORKER_ENDPOINTS],
    endpoint_count: usize,
    handler: Option<WorkerHandler>,
    worker_count: usize,
    on_enter: Option<WorkerEnterHook>,
    next_timeout_ns: Option<WorkerTimeoutNsHook>,
    on_timeout: Option<WorkerTimeoutHook>,
}

impl WorkerCfgSnapshot {
    const fn zeroed() -> Self {
        WorkerCfgSnapshot {
            endpoints: [0; MAX_WORKER_ENDPOINTS],
            endpoint_count: 0,
            handler: None,
            worker_count: 0,
            on_enter: None,
            next_timeout_ns: None,
            on_timeout: None,
        }
    }
}

// SAFETY: Written once before worker threads start, then read-only.
unsafe impl Send for WorkerCfgSnapshot {}
unsafe impl Sync for WorkerCfgSnapshot {}

/// VA bump allocator for worker regions.
static WORKER_VA_NEXT: AtomicU64 = AtomicU64::new(WORKER_REGION_BASE);

/// Allocate a contiguous VA region for one worker.
fn alloc_worker_va() -> u64 {
    WORKER_VA_NEXT.fetch_add(WORKER_REGION_STRIDE, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// run_workers -- main entry point
// ---------------------------------------------------------------------------

/// Spawn a pool of worker threads on a shared IPC endpoint.
///
/// The calling thread becomes worker #0 and enters the IPC loop (never returns).
/// Workers 1..N-1 are spawned as new kernel threads sharing the caller's
/// CSpace and VSpace.
///
/// # Safety
///
/// - `config.untyped` must be a valid Untyped cap with sufficient memory.
/// - `config.endpoint` must be a valid Endpoint cap.
/// - `handler` must be safe to call from any worker thread.
/// - Must be called after slot_alloc is initialized.
/// - THREAD_LOCAL_ACTIVE must be true (main thread TLS must be initialized).
pub unsafe fn run_workers(config: &WorkerConfig, handler: WorkerHandler) -> ! {
    // Verify TLS is active for the main thread
    if !tls::THREAD_LOCAL_ACTIVE.load(Ordering::Acquire) {
        crate::serial::serial_puts(
            b"[WORKER] FATAL: THREAD_LOCAL_ACTIVE not set - TLS not initialized\n",
        );
        loop {
            unsafe {
                syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
        }
    }

    let worker_count = config.worker_count.clamp(1, MAX_WORKERS);

    let period_us = if config.pool_period_us == 0 {
        DEFAULT_PERIOD_US
    } else {
        config.pool_period_us
    };

    // Budget per worker: auto-split from pool total, or use pool_budget_us directly.
    // Kernel SC tick granularity: budget_us/1000 must be >= 1 (i.e., >= 1000 us).
    let budget_per_worker = if config.pool_budget_us == 0 {
        let auto = period_us / (worker_count as u64);
        if auto < MIN_BUDGET_US {
            MIN_BUDGET_US
        } else {
            auto
        }
    } else {
        let per = config.pool_budget_us / (worker_count as u64);
        if per < MIN_BUDGET_US {
            MIN_BUDGET_US
        } else {
            per
        }
    };

    let stack_pages = if config.stack_pages == 0 {
        DEFAULT_STACK_PAGES
    } else {
        config.stack_pages
    };

    if config.endpoints.is_null()
        || config.endpoint_count == 0
        || config.endpoint_count > MAX_WORKER_ENDPOINTS
    {
        crate::serial::serial_puts(b"[WORKER] invalid endpoint count\n");
        loop {
            unsafe {
                syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
        }
    }

    // Store shared config snapshot
    unsafe {
        let cfg = &raw mut WORKER_CFG;
        let mut idx = 0usize;
        while idx < config.endpoint_count {
            (*cfg).endpoints[idx] = *config.endpoints.add(idx);
            idx += 1;
        }
        while idx < MAX_WORKER_ENDPOINTS {
            (*cfg).endpoints[idx] = 0;
            idx += 1;
        }
        (*cfg).endpoint_count = config.endpoint_count;
        (*cfg).handler = Some(handler);
        (*cfg).worker_count = worker_count;
        (*cfg).on_enter = config.on_enter;
        (*cfg).next_timeout_ns = config.next_timeout_ns;
        (*cfg).on_timeout = config.on_timeout;
    }

    // Worker #0 = main thread (already has TLS from init_main_thread_tls).
    // Mark it in our slot table and update the ThreadDesc owner.
    unsafe {
        let ws = &raw mut WORKER_SLOTS[0];
        (*ws).thread_pool_idx = 0;
        (*ws).active = true;

        let desc = tls::thread_desc(0);
        (*desc).owner = ThreadOwner::Worker;
    }

    // Spawn workers 1..N-1
    for i in 1..worker_count {
        unsafe {
            let err = spawn_worker(
                i,
                config.untyped,
                budget_per_worker,
                period_us,
                stack_pages,
                config.cspace_depth,
            );
            if err != 0 {
                crate::serial::serial_puts(b"[WORKER] spawn failed idx=");
                crate::serial::serial_dec(i as u64);
                crate::serial::serial_puts(b" err=");
                crate::serial::serial_hex(err as u64);
                crate::serial::serial_puts(b"\n");
            }
        }
    }

    // Main thread enters IPC loop as worker #0 (never returns)
    unsafe { worker_ipc_loop(0) }
}

// ---------------------------------------------------------------------------
// spawn_worker -- create one worker thread with full TLS
// ---------------------------------------------------------------------------

unsafe fn spawn_worker(
    worker_idx: usize,
    untyped: Cap,
    budget_us: u64,
    period_us: u64,
    stack_pages: u64,
    cspace_depth: u64,
) -> i32 {
    unsafe {
        // 1. Allocate a thread pool slot
        let pool_idx = match tls::alloc_thread_desc() {
            Some(idx) => idx,
            None => {
                crate::serial::serial_puts(b"[WORKER] thread pool full\n");
                return -1;
            }
        };

        let desc = tls::thread_desc(pool_idx);
        (*desc).owner = ThreadOwner::Worker;
        (*desc).thread_id = tls::next_thread_id();

        // 2. Allocate CNode slots: TCB, SC, IPC frame
        let base_slot = match slot_alloc::slot_alloc_consecutive(3) {
            Some(s) => s,
            None => {
                crate::serial::serial_puts(b"[WORKER] slot_alloc(3) failed\n");
                (*desc).state.store(TD_UNUSED, Ordering::Release);
                return -1;
            }
        };

        let tcb_slot = base_slot;
        let sc_slot = base_slot + 1;
        let ipc_frame_slot = base_slot + 2;

        (*desc).tcb_cap = tcb_slot;
        (*desc).sc_cap = sc_slot;
        (*desc).ipc_frame_cap = ipc_frame_slot;

        // 3. Retype kernel objects from untyped
        macro_rules! retype {
            ($obj:expr, $slot:expr, $name:expr) => {
                let err = invoke::untyped_retype(untyped, $obj, 0, $slot);
                if err != 0 {
                    crate::serial::serial_puts(b"[WORKER] retype ");
                    crate::serial::serial_puts($name);
                    crate::serial::serial_puts(b" failed\n");
                    rollback_worker(desc);
                    return err;
                }
            };
        }

        retype!(OBJ_TCB, tcb_slot, b"TCB");
        retype!(OBJ_SCHED_CONTEXT, sc_slot, b"SC");
        retype!(OBJ_FRAME, ipc_frame_slot, b"IPC frame");

        // 4. Allocate stack frames from untyped
        let stack_slots = match slot_alloc::slot_alloc_consecutive(stack_pages) {
            Some(s) => s,
            None => {
                crate::serial::serial_puts(b"[WORKER] slot_alloc(stack) failed\n");
                rollback_worker(desc);
                return -1;
            }
        };

        (*desc).stack_frame_base = stack_slots;
        (*desc).stack_frame_count = stack_pages;

        for p in 0..stack_pages {
            let err = invoke::untyped_retype(untyped, OBJ_FRAME, 0, stack_slots + p);
            if err != 0 {
                crate::serial::serial_puts(b"[WORKER] retype stack frame failed\n");
                rollback_worker(desc);
                return err;
            }
        }

        // 5. Allocate TLS region frames from untyped
        let tls_size = tls::thread_tls_region_size();
        let tls_pages = if tls_size > 0 { tls_size / 0x1000 } else { 1 };
        let tls_slots = match slot_alloc::slot_alloc_consecutive(tls_pages) {
            Some(s) => s,
            None => {
                crate::serial::serial_puts(b"[WORKER] slot_alloc(TLS) failed\n");
                rollback_worker(desc);
                return -1;
            }
        };

        (*desc).tls_frame_base = tls_slots;
        (*desc).tls_frame_count = tls_pages;

        for p in 0..tls_pages {
            let err = invoke::untyped_retype(untyped, OBJ_FRAME, 0, tls_slots + p);
            if err != 0 {
                crate::serial::serial_puts(b"[WORKER] retype TLS frame failed\n");
                rollback_worker(desc);
                return err;
            }
        }

        // 6. Allocate VA region and map pages
        let region_base = alloc_worker_va();
        // Layout: [guard 4K] [stack: stack_pages * 4K] [IPC buf: 4K] [TLS: tls_pages * 4K]
        let stack_va = region_base + 0x1000; // skip guard
        let ipc_va = stack_va + stack_pages * 0x1000;
        let tls_va = ipc_va + 0x1000;

        (*desc).stack_base = stack_va;
        (*desc).stack_size = stack_pages * 0x1000;
        (*desc).ipc_buf_vaddr = ipc_va;
        (*desc).tls_region = tls_va;
        (*desc).tls_region_size = tls_pages * 0x1000;

        // Map stack frames
        for p in 0..stack_pages {
            let err = invoke::vspace_map(
                CAP_SELF_VSPACE,
                stack_slots + p,
                stack_va + p * 0x1000,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                crate::serial::serial_puts(b"[WORKER] stack map failed\n");
                rollback_worker(desc);
                return err;
            }
        }

        // Map IPC buffer frame
        let err = invoke::vspace_map(
            CAP_SELF_VSPACE,
            ipc_frame_slot,
            ipc_va,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            crate::serial::serial_puts(b"[WORKER] IPC map failed\n");
            rollback_worker(desc);
            return err;
        }

        // Map TLS frames
        for p in 0..tls_pages {
            let err = invoke::vspace_map(
                CAP_SELF_VSPACE,
                tls_slots + p,
                tls_va + p * 0x1000,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                crate::serial::serial_puts(b"[WORKER] TLS map failed\n");
                rollback_worker(desc);
                return err;
            }
        }

        // 7. Initialize TLS block within the mapped TLS region
        let (tp, tls_block) = init_worker_tls(tls_va, tls_pages * 0x1000, desc);

        (*desc).tls_ptr = tls_block;
        (*tls_block).desc = desc as *mut u8;
        (*tls_block).thread_id = (*desc).thread_id;
        (*tls_block).ipc_ctx.ipc_buffer = ipc_va as *mut IpcBuffer;
        (*tls_block).ipc_ctx.send_cap_count = 0;

        // 8. Configure TCB: share CSpace and VSpace
        let err = if cspace_depth > 0 {
            invoke::tcb_set_space_with_depth(
                tcb_slot,
                CAP_SELF_CSPACE,
                CAP_SELF_VSPACE,
                cspace_depth,
            )
        } else {
            invoke::tcb_set_space(tcb_slot, CAP_SELF_CSPACE, CAP_SELF_VSPACE)
        };
        if err != 0 {
            crate::serial::serial_puts(b"[WORKER] tcb_set_space failed\n");
            rollback_worker(desc);
            return err;
        }

        // Set IPC buffer on TCB
        let err = invoke::tcb_set_ipc_buffer(tcb_slot, ipc_va);
        if err != 0 {
            crate::serial::serial_puts(b"[WORKER] tcb_set_ipc_buffer failed\n");
            rollback_worker(desc);
            return err;
        }

        // Set TLS base on TCB
        let err = invoke::tcb_set_tls_base(tcb_slot, tp);
        if err != 0 {
            crate::serial::serial_puts(b"[WORKER] tcb_set_tls_base failed\n");
            rollback_worker(desc);
            return err;
        }

        // 9. Set up stack for trampoline entry.
        // Push worker_idx and pool_idx onto the stack for the trampoline.
        // aarch64 requires SP to be 16-byte aligned; use 32 bytes (4 slots)
        // with padding to satisfy both architectures.
        let stack_top = stack_va + stack_pages * 0x1000;
        let trampoline_rsp = stack_top - 32; // 4 x 8 bytes: [worker_idx, pool_idx, fake_ret, pad]
        let args = trampoline_rsp as *mut u64;
        *args = worker_idx as u64; // arg 0: worker index
        *(args.add(1)) = pool_idx as u64; // arg 1: thread pool index
        *(args.add(2)) = 0; // fake return address (x86_64)
        *(args.add(3)) = 0; // padding (16-byte alignment)

        let err = invoke::tcb_configure(
            tcb_slot,
            worker_entry_trampoline as *const () as u64,
            trampoline_rsp,
            ipc_va,
        );
        if err != 0 {
            crate::serial::serial_puts(b"[WORKER] tcb_configure failed\n");
            rollback_worker(desc);
            return err;
        }

        // 10. Configure scheduling context and bind to TCB
        let err = invoke::sc_configure(sc_slot, budget_us, period_us);
        if err != 0 {
            crate::serial::serial_puts(b"[WORKER] sc_configure failed\n");
            rollback_worker(desc);
            return err;
        }

        let err = invoke::sc_bind(sc_slot, tcb_slot);
        if err != 0 {
            crate::serial::serial_puts(b"[WORKER] sc_bind failed\n");
            rollback_worker(desc);
            return err;
        }

        // 11. Record in worker slot table
        let ws = &raw mut WORKER_SLOTS[worker_idx];
        (*ws).thread_pool_idx = pool_idx;
        (*ws).active = true;

        // 12. Resume the worker thread
        let err = invoke::tcb_resume(tcb_slot);
        if err != 0 {
            crate::serial::serial_puts(b"[WORKER] tcb_resume failed\n");
            (*ws).active = false;
            rollback_worker(desc);
            return err;
        }

        0
    }
}

// ---------------------------------------------------------------------------
// TLS initialization for worker threads
// ---------------------------------------------------------------------------

/// Initialize the TLS region for a spawned worker.
///
/// Returns (tp_value, tls_block_ptr) for configuring tcb_set_tls_base
/// and the worker's IPC context.
///
/// # Safety
/// `tls_va` must be mapped and writable with at least `tls_size` bytes.
unsafe fn init_worker_tls(
    tls_va: u64,
    tls_size: u64,
    _desc: *mut ThreadDesc,
) -> (u64, *mut ThreadLocalBlock) {
    unsafe {
        let tls_memsz = tls::static_tls_total_memsz();
        let tls_align = tls::static_tls_align().max(16);
        let tcb_size = ::core::mem::size_of::<ThreadLocalBlock>() as u64;
        let runtime_tcb_align = ::core::mem::align_of::<ThreadLocalBlock>() as u64;

        // Zero the entire TLS region
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
                tp.saturating_add(abi_size).saturating_add(tls_memsz),
                runtime_tcb_align,
            );
            let tls_block = tcb_addr as *mut ThreadLocalBlock;
            (tp, tls_block)
        };

        // Copy static TLS template data
        tls::initialize_static_tls_for_tp(tp);
        tls::install_runtime_tcb_anchor(tp, tls_block);

        // Set self-pointer (x86_64 TLS ABI)
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
fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.saturating_add(align - 1) & !(align - 1)
    }
}

// ---------------------------------------------------------------------------
// Worker rollback on spawn failure
// ---------------------------------------------------------------------------

/// Roll back a partially created worker. Unmaps pages, deletes caps, returns
/// the thread pool slot.
unsafe fn rollback_worker(desc: *mut ThreadDesc) {
    unsafe {
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
        // Delete caps
        if (*desc).tcb_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, (*desc).tcb_cap);
        }
        if (*desc).sc_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, (*desc).sc_cap);
        }
        if (*desc).ipc_frame_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, (*desc).ipc_frame_cap);
        }
        if (*desc).tcb_cap != 0 {
            slot_alloc::slot_free_range((*desc).tcb_cap, 3);
        }
        if (*desc).stack_frame_base != 0 {
            for p in 0..(*desc).stack_frame_count {
                invoke::cnode_delete(CAP_SELF_CSPACE, (*desc).stack_frame_base + p);
            }
            slot_alloc::slot_free_range((*desc).stack_frame_base, (*desc).stack_frame_count);
        }
        if (*desc).tls_frame_base != 0 {
            for p in 0..(*desc).tls_frame_count {
                invoke::cnode_delete(CAP_SELF_CSPACE, (*desc).tls_frame_base + p);
            }
            slot_alloc::slot_free_range((*desc).tls_frame_base, (*desc).tls_frame_count);
        }

        (*desc).state.store(TD_UNUSED, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Worker entry trampoline (naked -- no compiler prologue)
// ---------------------------------------------------------------------------

/// Naked trampoline for worker thread entry.
///
/// x86_64 stack on entry: [RSP+0]=worker_idx, [RSP+8]=pool_idx, [RSP+16]=0
/// aarch64: same layout, popped via ldp pairs.
#[unsafe(no_mangle)]
#[unsafe(naked)]
unsafe extern "C" fn worker_entry_trampoline() {
    #[cfg(target_arch = "x86_64")]
    ::core::arch::naked_asm!(
        "pop rdi",          // worker_idx -> arg 0
        "pop rsi",          // pool_idx -> arg 1
        "pop rdx",          // discard fake return address
        "jmp {helper}",
        helper = sym worker_entry_helper,
    );
    #[cfg(target_arch = "aarch64")]
    ::core::arch::naked_asm!(
        "ldp x0, x1, [sp], #16",  // x0 = worker_idx, x1 = pool_idx
        "ldr x2, [sp], #8",       // discard fake return address
        "b {helper}",
        helper = sym worker_entry_helper,
    );
}

/// Helper called by the naked trampoline.
unsafe extern "C" fn worker_entry_helper(worker_idx: u64, pool_idx: u64) -> ! {
    let w_idx = worker_idx as usize;
    let _p_idx = pool_idx as usize;

    unsafe {
        // Mark THREAD_LOCAL_ACTIVE so current_tls() works on this thread
        tls::THREAD_LOCAL_ACTIVE.store(true, Ordering::Release);

        crate::udebug!(|_lb| {
            _lb.str(b"[WORKER] worker ");
            _lb.dec(worker_idx);
            _lb.str(b" started (pool=");
            _lb.dec(pool_idx);
            _lb.str(b")\n");
        });

        worker_ipc_loop(w_idx)
    }
}

// ---------------------------------------------------------------------------
// Worker IPC loop
// ---------------------------------------------------------------------------

/// Run the recv -> handler -> reply_recv loop for a worker.
///
/// Worker #0 also reaps exited workers on each iteration.
unsafe fn worker_ipc_loop(worker_idx: usize) -> ! {
    unsafe {
        let cfg = &*(&raw const WORKER_CFG);
        let endpoints = (&cfg.endpoints) as *const Cap;
        let endpoint_count = cfg.endpoint_count;
        let handler = match cfg.handler {
            Some(h) => h,
            None => {
                crate::serial::serial_puts(b"[WORKER] no handler configured\n");
                loop {
                    syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
                }
            }
        };
        let on_enter = cfg.on_enter;
        let next_timeout_ns = cfg.next_timeout_ns;
        let on_timeout = cfg.on_timeout;

        let ctx = crate::current_ipc_ctx();
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        let mut badge: u64 = 0;
        let mut recv_source: u64 = 0;

        if let Some(enter) = on_enter {
            enter(ctx, worker_idx);
        }

        loop {
            let first_timeout_ns = match next_timeout_ns {
                Some(f) => f(ctx, worker_idx),
                None => 0,
            };
            let err = if first_timeout_ns == 0 {
                ipc::recv_any_ctx(
                    ctx,
                    endpoints,
                    endpoint_count,
                    &raw mut msg,
                    &raw mut badge,
                    &raw mut recv_source,
                )
            } else {
                ipc::recv_any_timed_ctx(
                    ctx,
                    endpoints,
                    endpoint_count,
                    first_timeout_ns,
                    &raw mut msg,
                    &raw mut badge,
                    &raw mut recv_source,
                )
            };
            if err == TRONA_CANCELLED as i32 || err == TRONA_TIMED_OUT as i32 {
                if let Some(timeout_hook) = on_timeout {
                    timeout_hook(ctx, worker_idx);
                }
                continue;
            }
            if err != 0 {
                crate::serial::serial_puts(b"[WORKER] initial recv failed\n");
                worker_exit(worker_idx);
            }
            break;
        }

        loop {
            let control = handler(ctx, &raw mut msg, badge, recv_source, &raw mut reply);

            if let WorkerLoopControl::Exit = control {
                worker_exit(worker_idx);
            }

            let timeout_ns = match next_timeout_ns {
                Some(f) => f(ctx, worker_idx),
                None => 0,
            };
            let err = match control {
                WorkerLoopControl::Reply => {
                    if timeout_ns == 0 {
                        ipc::reply_recv_any_ctx(
                            ctx,
                            endpoints,
                            endpoint_count,
                            &raw const reply,
                            &raw mut msg,
                            &raw mut badge,
                            &raw mut recv_source,
                        )
                    } else {
                        ipc::reply_recv_any_timed_ctx(
                            ctx,
                            endpoints,
                            endpoint_count,
                            timeout_ns,
                            &raw const reply,
                            &raw mut msg,
                            &raw mut badge,
                            &raw mut recv_source,
                        )
                    }
                }
                WorkerLoopControl::SkipReply => {
                    if timeout_ns == 0 {
                        ipc::recv_any_ctx(
                            ctx,
                            endpoints,
                            endpoint_count,
                            &raw mut msg,
                            &raw mut badge,
                            &raw mut recv_source,
                        )
                    } else {
                        ipc::recv_any_timed_ctx(
                            ctx,
                            endpoints,
                            endpoint_count,
                            timeout_ns,
                            &raw mut msg,
                            &raw mut badge,
                            &raw mut recv_source,
                        )
                    }
                }
                WorkerLoopControl::Exit => unreachable!(),
            };

            if err == TRONA_CANCELLED as i32 || err == TRONA_TIMED_OUT as i32 {
                if let Some(timeout_hook) = on_timeout {
                    timeout_hook(ctx, worker_idx);
                }
                continue;
            }
            if err != 0 {
                // receive recovery failed
                let err2 = ipc::recv_any_ctx(
                    ctx,
                    endpoints,
                    endpoint_count,
                    &raw mut msg,
                    &raw mut badge,
                    &raw mut recv_source,
                );
                if err2 != 0 {
                    crate::serial::serial_puts(b"[WORKER] recv recovery failed\n");
                    worker_exit(worker_idx);
                }
            }

            // Worker #0 reaps exited workers
            if worker_idx == 0 {
                reap_exited_workers();
            }
        }
    }
}

/// Return the worker slot index for the current thread, or 0 for the main thread.
pub fn current_worker_index() -> usize {
    unsafe {
        let tls = match tls::current_tls() {
            Some(t) => t,
            None => return 0,
        };
        let desc = (*tls).desc;
        if desc.is_null() {
            return 0;
        }
        let mut idx = 0usize;
        while idx < MAX_WORKERS {
            let ws = &*(&raw const WORKER_SLOTS[idx]);
            if ws.active {
                let pool_desc = tls::thread_desc(ws.thread_pool_idx);
                if pool_desc as *mut u8 == desc {
                    return idx;
                }
            }
            idx += 1;
        }
        0
    }
}

// ---------------------------------------------------------------------------
// Worker exit and reaper
// ---------------------------------------------------------------------------

/// Exit a worker thread.
///
/// Worker #0: process must terminate (infinite yield).
/// Workers 1+: mark TD_EXITED and self-suspend for reaping.
unsafe fn worker_exit(worker_idx: usize) -> ! {
    unsafe {
        if worker_idx == 0 {
            crate::serial::serial_puts(b"[WORKER] worker #0 exit -- _exit(1)\n");
            // Worker #0 is the main thread. Servers should never let it exit.
            // Infinite yield as defense — substrate has no _exit.
            loop {
                syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
        }

        // Look up thread pool index from worker slot table
        let ws = &*(&raw const WORKER_SLOTS[worker_idx]);
        let pool_idx = ws.thread_pool_idx;
        let desc = tls::thread_desc(pool_idx);

        (*desc).state.store(TD_EXITED, Ordering::Release);

        // Reaper cleans up after the current worker stops itself.
        crate::syscall::thread_exit();
    }
}

/// Reap exited worker threads.
///
/// Scans all worker slots (1..worker_count). For each whose ThreadDesc is
/// TD_EXITED, CAS to TD_REAPING and call `tls::cleanup_thread()`.
fn reap_exited_workers() {
    unsafe {
        let worker_count = (*(&raw const WORKER_CFG)).worker_count;

        for i in 1..worker_count {
            let ws = &*(&raw const WORKER_SLOTS[i]);
            if !ws.active {
                continue;
            }

            let desc = tls::thread_desc(ws.thread_pool_idx);
            if (*desc)
                .state
                .compare_exchange(TD_EXITED, TD_REAPING, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Ensure TCB is suspended before cleanup
                if (*desc).tcb_cap != 0 {
                    invoke::tcb_suspend((*desc).tcb_cap);
                }

                tls::cleanup_thread(desc);

                // Mark worker slot as inactive
                let ws_mut = &raw mut WORKER_SLOTS[i];
                (*ws_mut).active = false;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public query API
// ---------------------------------------------------------------------------

/// Return the number of currently active workers.
pub fn active_worker_count() -> usize {
    let mut count = 0;
    unsafe {
        let worker_count = (*(&raw const WORKER_CFG)).worker_count;
        for i in 0..worker_count {
            let ws = &*(&raw const WORKER_SLOTS[i]);
            if ws.active {
                let desc = tls::thread_desc(ws.thread_pool_idx);
                if (*desc).state.load(Ordering::Relaxed) == TD_RUNNING {
                    count += 1;
                }
            }
        }
    }
    count
}
