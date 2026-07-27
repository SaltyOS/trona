//! Personality-neutral in-process thread spawn helper.
//!
//! A subsystem-neutral service that needs a background worker thread uses
//! [`spawn_fn`] here instead of reaching for `trona_posix::pthread_create`.
//! pthread is a POSIX-personality abstraction; a driver / core service that
//! must remain personality-agnostic should depend only on the substrate.
//!
//! The helper drives the same kernel invocations directly (TCB +
//! SchedContext retype from untyped, CSpace/VSpace shared with the
//! caller, TLS block installed so `current_ipc_ctx` / `Mutex` /
//! `uerror!` work from the spawned thread) and runs a caller-supplied
//! entry function on its own stack — IPC dispatch is the caller's
//! concern. The supporting bookkeeping (VA stride bump allocator,
//! TLS region init, partial-spawn rollback) lives in
//! [`crate::thread::worker`].
//!
//! The caller keeps the returned [`ThreadHandle`] for teardown. Thread
//! exit is the entry function's responsibility (call [`thread_exit`]
//! explicitly, or fall off the entry function's tail — the trampoline
//! invokes `thread_exit` on return).

use super::cap::{OwnedSlotRange, ThreadCap};
use crate::core::slot_alloc;
use crate::core::slot_pool::SlotPool;
use crate::thread::tls;
use crate::thread::tls::{TD_UNUSED, ThreadOwner};
use crate::thread::worker::{alloc_worker_va, init_worker_tls, rollback_worker};
use core::sync::atomic::Ordering;
use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::init::{INIT_THREAD, INIT_THREAD_SUB_CREATE, INIT_THREAD_SUB_EXIT};
use trona_protocol::posix_abi::mm::{MAP_ANONYMOUS, MAP_LAZY, MAP_PRIVATE, MAP_STACK};

const OBJ_TCB: u64 = uapi::KERNITE_OBJ_TCB as u64;
const OBJ_SCHED_CONTEXT: u64 = uapi::KERNITE_OBJ_SCHED_CONTEXT as u64;
const OBJ_FRAME: u64 = uapi::KERNITE_OBJ_FRAME as u64;
const CAP_SELF_CSPACE: CapRef = CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64);
const CAP_SELF_VSPACE: CapRef = CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64);
const VSPACE_FLAG_USER: u64 = uapi::KERNITE_PAGE_FLAG_USER as u64;
const VSPACE_FLAG_WRITABLE: u64 = uapi::KERNITE_PAGE_FLAG_WRITABLE as u64;
const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;

/// Default stack pages per spawned thread.
pub const DEFAULT_STACK_PAGES: u64 = 16;
/// Default scheduling period (100 ms).
pub const DEFAULT_PERIOD_NS: u64 = 100_000_000;
/// Default scheduling budget per period (10 ms).
pub const DEFAULT_BUDGET_NS: u64 = 10_000_000;
/// Minimum scheduling budget accepted by the kernel (1 ms).
pub const MIN_BUDGET_NS: u64 = 1_000_000;

/// Handle for a spawned thread. Caps stay live for the thread's lifetime.
#[derive(Clone, Copy)]
pub struct ThreadHandle {
    /// TCB capability slot.
    pub tcb: Cap,
    /// SchedContext capability slot.
    pub sc: Cap,
    /// Thread pool descriptor index (into `substrate::tls`).
    pub pool_idx: usize,
}

/// Parameters for [`spawn_fn`]. Zero fields fall back to the
/// `DEFAULT_*` constants above.
pub struct SpawnConfig {
    /// Untyped authority to retype the new thread's TCB / SC / frames from.
    /// When null ([`CapRef::is_null`]), [`spawn_fn`] uses the normal process
    /// supervisor: stack/TLS/IPC memory is mapped through mmsrv and TCB / SC
    /// creation is delegated to init's `INIT_THREAD_CREATE` path.
    pub untyped: CapRef,
    /// Stack pages. 0 → `DEFAULT_STACK_PAGES` (16 × 4 KiB).
    pub stack_pages: u64,
    /// Scheduling budget in nanoseconds. 0 → `DEFAULT_BUDGET_NS`.
    pub budget_ns: u64,
    /// Scheduling period in nanoseconds. 0 → `DEFAULT_PERIOD_NS`.
    pub period_ns: u64,
    /// Optional CNode guard depth passed through to
    /// `tcb_set_space_with_depth`. 0 → use `tcb_set_space` with no
    /// explicit depth.
    pub cspace_depth: u64,
    /// Optional private slot pool. When `Some`, `spawn_fn`'s
    /// consecutive-slot reservations (TCB+SC+IPC, stack pages, TLS
    /// pages) come out of this pool instead of the process-wide
    /// `slot_alloc`. Used by callers that must keep their thread
    /// reservations isolated — e.g. the supervisor `IpcTimer` thread,
    /// which would otherwise lose its slot budget to a partially
    /// successful lifecycle worker spawn.
    pub slot_pool: Option<&'static SlotPool>,
}

impl SpawnConfig {
    /// Minimal config: inherits caller's CSpace/VSpace, default
    /// stack/budget/period.
    #[inline]
    pub const fn new(untyped: CapRef) -> Self {
        SpawnConfig {
            untyped,
            stack_pages: 0,
            budget_ns: 0,
            period_ns: 0,
            cspace_depth: 0,
            slot_pool: None,
        }
    }

    /// Builder: route `spawn_fn`'s slot reservations through `pool`
    /// instead of the global `slot_alloc`. The pool must outlive the
    /// spawned thread (typically a `static SlotPool`).
    #[inline]
    pub const fn with_slot_pool(mut self, pool: &'static SlotPool) -> Self {
        self.slot_pool = Some(pool);
        self
    }

    /// Resolve the runtime-provided bootstrap untyped and return a
    /// minimal `SpawnConfig` drawing its kernel objects from it. Callers
    /// never name a slot or cap directly: the untyped is read from the
    /// child's `AT_SALTYOS_STARTUP` auxv entry via
    /// [`crate::runtime_get_bootstrap_untyped`].
    ///
    /// The bootstrap untyped is sized for RTLD plus the shared-library
    /// window; it is adequate for a small worker pool but may exhaust
    /// under aggressive `MAX_WORKERS` values. Callers iterate through
    /// `spawn_fn` and stop on the first [`SpawnError::InvokeFailed`],
    /// which is the existing contract.
    #[inline]
    pub fn for_runtime_bootstrap_untyped() -> Result<Self, SpawnError> {
        match crate::runtime_get_bootstrap_untyped() {
            Some(untyped) => Ok(SpawnConfig::new(crate::core::slot_alloc::resolved_cap_ref(
                untyped,
            ))),
            None => Err(SpawnError::NoBootstrapUntyped),
        }
    }

    /// Prefer the runtime-provided bootstrap untyped when a spawner
    /// deliberately installed one; otherwise use the steady-state
    /// supervisor thread API. Regular manifest services should use this
    /// constructor so they do not depend on raw untyped authority just to
    /// run an internal worker thread.
    #[inline]
    pub fn for_runtime_thread() -> Self {
        match crate::runtime_get_bootstrap_untyped() {
            Some(untyped) => SpawnConfig::new(crate::core::slot_alloc::resolved_cap_ref(untyped)),
            None => SpawnConfig::new(CapRef::NULL),
        }
    }
}

/// Reserve `n` consecutive CSpace slots for a `spawn_fn` invocation.
/// Routes through `config.slot_pool` when set, otherwise the global
/// `slot_alloc`. Centralised so adding new pool kinds (per-untyped,
/// per-tenant) does not need to touch the spawn body.
#[inline]
fn alloc_consecutive_for(config: &SpawnConfig, n: u64) -> Option<Cap> {
    match config.slot_pool {
        Some(pool) => pool.alloc_consecutive(n),
        None => slot_alloc::slot_alloc_consecutive(n),
    }
}

fn align_down(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value & !(align - 1)
    }
}

unsafe fn init_thread_create_call(
    entry_pc: u64,
    entry_rsp: u64,
    reserve_top: u64,
    tls_base: u64,
    ipc_buf_vaddr: u64,
    attr_flags: u64,
    stack_base: u64,
    stack_guard_bottom: u64,
    budget_ns: u64,
    period_ns: u64,
) -> Result<u16, SpawnError> {
    unsafe {
        let init_ep = crate::client::caps::init_ep().addr();
        if init_ep == 0 {
            return Err(SpawnError::InvokeFailed(uapi::KERNITE_ERR_NOT_FOUND as i32));
        }

        let mut req = TronaMsg::zeroed();
        req.label = INIT_THREAD;
        req.length = 11;
        req.regs[0] = INIT_THREAD_SUB_CREATE;
        req.regs[1] = entry_pc;
        req.regs[2] = entry_rsp;
        req.regs[3] = tls_base;
        req.regs[4] = ipc_buf_vaddr;
        req.regs[5] = attr_flags;
        req.regs[6] = stack_base;
        req.regs[7] = stack_guard_bottom;
        req.regs[8] = reserve_top;
        req.regs[9] = budget_ns;
        req.regs[10] = period_ns;

        let mut reply = TronaMsg::zeroed();
        // Single blocking MP_CALL — no RESTART/INTERRUPTED re-send (kernel
        // reply-wait owns resume; re-sending would duplicate the spawn request).
        let err = ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            init_ep,
            &raw const req,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(SpawnError::InvokeFailed(err));
        }

        if reply.label != trona_protocol::common::TRONA_OK {
            return Err(SpawnError::InvokeFailed(reply.label as i32));
        }
        Ok(reply.regs[0] as u16)
    }
}

unsafe fn notify_init_thread_exit(tid: u16, status: i32) {
    if tid == 0 {
        return;
    }
    unsafe {
        let init_ep = crate::client::caps::init_ep().addr();
        if init_ep == 0 {
            return;
        }
        let mut req = TronaMsg::zeroed();
        req.label = INIT_THREAD;
        req.length = 3;
        req.regs[0] = INIT_THREAD_SUB_EXIT;
        req.regs[1] = tid as u64;
        req.regs[2] = status as u64;
        let _ = ipc::mp_write_ctx(crate::current_ipc_ctx(), init_ep, &raw const req);
    }
}

/// Errors that can happen inside [`spawn_fn`]. Each variant maps to an
/// approximate errno so the caller can surface a useful diagnostic.
#[derive(Clone, Copy, Debug)]
pub enum SpawnError {
    /// No free thread pool descriptor slot.
    ThreadPoolFull,
    /// `slot_alloc::slot_alloc_consecutive` failed — CSpace exhausted.
    NoSlot,
    /// An `invoke::*` returned a non-zero error. Carries the raw code.
    InvokeFailed(i32),
    /// TLS for the calling (main) thread was never initialised.
    TlsInactive,
    /// `crate::runtime_get_bootstrap_untyped()` returned `None`. The
    /// `AT_SALTYOS_STARTUP` auxv entry is missing or the saved auxv
    /// pointer is null — either would mean the child's CRT startup
    /// block is corrupt.
    NoBootstrapUntyped,
}

impl SpawnError {
    /// Collapse to a raw syscall error for logging purposes.
    pub fn as_i32(&self) -> i32 {
        match *self {
            SpawnError::ThreadPoolFull => -1,
            SpawnError::NoSlot => -1,
            SpawnError::InvokeFailed(e) => e,
            SpawnError::TlsInactive => -1,
            SpawnError::NoBootstrapUntyped => -1,
        }
    }
}

unsafe fn spawn_fn_via_init(
    entry: unsafe extern "C" fn(*mut u8) -> (),
    arg: *mut u8,
    stack_pages: u64,
    budget_ns: u64,
    period_ns: u64,
) -> Result<ThreadHandle, SpawnError> {
    unsafe {
        let pool_idx = tls::alloc_thread_desc().ok_or(SpawnError::ThreadPoolFull)?;
        let desc = tls::thread_desc(pool_idx);
        (*desc).owner = ThreadOwner::Worker;
        (*desc).thread_id = tls::next_thread_id();
        (*desc).mmsrv_backed = 1;
        (*desc).init_tid = 0;
        (*desc).tcb_cap = ThreadCap::None;
        (*desc).sc_cap = ThreadCap::None;
        (*desc).ipc_frame_cap = ThreadCap::None;
        (*desc).stack_frames = None;
        (*desc).tls_frames = None;
        (*desc).stack_base = 0;
        (*desc).stack_size = 0;
        (*desc).tls_region = 0;
        (*desc).tls_region_size = 0;
        (*desc).ipc_buf_vaddr = 0;
        (*desc).tls_ptr = core::ptr::null_mut();

        let stack_size = stack_pages
            .checked_mul(0x1000)
            .ok_or(SpawnError::InvokeFailed(
                uapi::KERNITE_ERR_INVALID_ARGUMENT as i32,
            ))?;
        let stack_addr = match crate::client::mm::mmap(
            core::ptr::null_mut(),
            stack_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_LAZY | MAP_STACK,
            -1,
            0,
        ) {
            Ok(ptr) if !ptr.is_null() => ptr as u64,
            Ok(_) => {
                rollback_worker(desc);
                return Err(SpawnError::InvokeFailed(
                    uapi::KERNITE_ERR_OUT_OF_MEMORY as i32,
                ));
            }
            Err(e) => {
                rollback_worker(desc);
                return Err(SpawnError::InvokeFailed(e as i32));
            }
        };
        (*desc).stack_base = stack_addr;
        (*desc).stack_size = stack_size;

        let tls_size = tls::thread_tls_region_size();
        let tls_size = if tls_size > 0 { tls_size } else { 0x1000 };
        if tls_size >= stack_size {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(
                uapi::KERNITE_ERR_OUT_OF_MEMORY as i32,
            ));
        }
        let stack_top = stack_addr + stack_size;
        let tls_va = align_down(stack_top - tls_size, 0x1000);
        (*desc).tls_region = tls_va;
        (*desc).tls_region_size = tls_size;

        let (tp, tls_block) = init_worker_tls(tls_va, tls_size, desc);
        (*desc).tls_ptr = tls_block;
        (*tls_block).desc = desc as *mut u8;
        (*tls_block).thread_id = (*desc).thread_id;

        let ipc_buf = match crate::client::mm::mmap(
            core::ptr::null_mut(),
            0x1000,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ) {
            Ok(ptr) if !ptr.is_null() => ptr as u64,
            Ok(_) => {
                rollback_worker(desc);
                return Err(SpawnError::InvokeFailed(
                    uapi::KERNITE_ERR_OUT_OF_MEMORY as i32,
                ));
            }
            Err(e) => {
                rollback_worker(desc);
                return Err(SpawnError::InvokeFailed(e as i32));
            }
        };
        (*desc).ipc_buf_vaddr = ipc_buf;
        trona_kernel::ipc::ipc_context_init(
            &raw mut (*tls_block).ipc_ctx,
            ipc_buf as *mut uapi::kernite_ipc_buffer,
        );

        let user_rsp = tls_va & !0xF;
        if user_rsp <= stack_addr + 32 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(
                uapi::KERNITE_ERR_OUT_OF_MEMORY as i32,
            ));
        }
        let trampoline_rsp = user_rsp - 32;
        let args = trampoline_rsp as *mut u64;
        *args = entry as *const () as u64;
        *(args.add(1)) = arg as u64;
        *(args.add(2)) = 0;
        *(args.add(3)) = 0;

        let init_tid = match init_thread_create_call(
            thread_entry_trampoline as *const () as u64,
            trampoline_rsp,
            stack_top,
            tp,
            ipc_buf,
            1,
            stack_addr,
            0,
            budget_ns,
            period_ns,
        ) {
            Ok(tid) => tid,
            Err(e) => {
                rollback_worker(desc);
                return Err(e);
            }
        };
        (*desc).init_tid = init_tid;

        Ok(ThreadHandle {
            tcb: 0,
            sc: 0,
            pool_idx,
        })
    }
}

/// Spawn a new in-process thread running `entry(arg)`.
///
/// The spawned thread shares CSpace / VSpace with the caller, gets its
/// own stack, IPC buffer, TLS block, and SchedContext. `entry` runs on
/// the new thread's stack; if it returns, the trampoline calls
/// [`thread_exit`] so the thread is cleanly reaped.
///
/// # Safety
///
/// - When `config.untyped != 0`, it must be a valid Untyped cap with
///   enough headroom for the required frames. When it is zero, init and
///   mmsrv must be reachable through the startup cap table.
/// - `entry` must be safe to call from a thread sharing the caller's
///   CSpace/VSpace.
/// - The caller's TLS must already be active (normal for any process
///   that entered `main`).
pub unsafe fn spawn_fn(
    entry: unsafe extern "C" fn(*mut u8) -> (),
    arg: *mut u8,
    config: &SpawnConfig,
) -> Result<ThreadHandle, SpawnError> {
    unsafe {
        if !tls::THREAD_LOCAL_ACTIVE.load(Ordering::Acquire) {
            return Err(SpawnError::TlsInactive);
        }

        let stack_pages = if config.stack_pages == 0 {
            DEFAULT_STACK_PAGES
        } else {
            config.stack_pages
        };
        let period_ns = if config.period_ns == 0 {
            DEFAULT_PERIOD_NS
        } else {
            config.period_ns
        };
        let budget_ns = if config.budget_ns == 0 {
            DEFAULT_BUDGET_NS
        } else if config.budget_ns < MIN_BUDGET_NS {
            MIN_BUDGET_NS
        } else {
            config.budget_ns
        };

        if config.untyped.is_null() {
            return spawn_fn_via_init(entry, arg, stack_pages, budget_ns, period_ns);
        }

        let pool_idx = tls::alloc_thread_desc().ok_or(SpawnError::ThreadPoolFull)?;
        let desc = tls::thread_desc(pool_idx);
        (*desc).owner = ThreadOwner::Worker;
        (*desc).thread_id = tls::next_thread_id();
        (*desc).init_tid = 0;
        (*desc).mmsrv_backed = 0;

        // Allocate consecutive CSpace slots for TCB + SC + IPC frame.
        let base_slot = match alloc_consecutive_for(config, 3) {
            Some(s) => s,
            None => {
                (*desc).state.store(TD_UNUSED, Ordering::Release);
                return Err(SpawnError::NoSlot);
            }
        };
        let tcb_slot = base_slot;
        let sc_slot = base_slot + 1;
        let ipc_frame_slot = base_slot + 2;
        // Own the three slots locally and operate on them through borrows.
        // They move into the descriptor only once the spawn fully succeeds, so
        // any failure below drops them here (delete + free) while the
        // descriptor's cap fields stay empty — `rollback_worker` only has VA
        // mappings to undo.
        let cap_depth = slot_alloc::slot_invoke_depth(base_slot);
        // Slots drawn from a private `SlotPool` must not be returned to the
        // global allocator on teardown (the pool owns the index and has no
        // reclaim path); tag the owned handles with the matching origin so
        // their `Drop` deletes the cap without a stray global `slot_free`.
        let slot_origin = if config.slot_pool.is_some() {
            slot_alloc::SlotOrigin::Pool
        } else {
            slot_alloc::SlotOrigin::Global
        };
        // SAFETY (within this fn's enclosing unsafe block): tcb_slot / sc_slot /
        // ipc_frame_slot are distinct slots just allocated for this worker at
        // `cap_depth`, each retyped below and owned solely by the handle adopting
        // it; `slot_origin` matches the pool/global source so each Drop reclaims.
        let tcb = slot_alloc::OwnedCap::from_raw_in(tcb_slot, cap_depth, slot_origin);
        let sc = slot_alloc::OwnedCap::from_raw_in(sc_slot, cap_depth, slot_origin);
        let ipc = slot_alloc::OwnedCap::from_raw_in(ipc_frame_slot, cap_depth, slot_origin);

        // Retype kernel objects from untyped.
        macro_rules! retype {
            ($obj:expr, $slot:expr) => {
                let err = invoke::untyped_retype(config.untyped, $obj, 0, $slot);
                if err != 0 {
                    rollback_worker(desc);
                    return Err(SpawnError::InvokeFailed(err));
                }
            };
        }
        retype!(OBJ_TCB, tcb_slot);
        retype!(OBJ_SCHED_CONTEXT, sc_slot);
        retype!(OBJ_FRAME, ipc_frame_slot);

        // Stack frames.
        let stack_slots = match alloc_consecutive_for(config, stack_pages) {
            Some(s) => s,
            None => {
                rollback_worker(desc);
                return Err(SpawnError::NoSlot);
            }
        };
        // SAFETY (within this fn's enclosing unsafe block): stack_slots..+stack_pages
        // is a fresh consecutive run from alloc_consecutive_for, owned solely by
        // this range and retyped below; slot_origin matches its source.
        let stack = OwnedSlotRange::from_consecutive_in(stack_slots, stack_pages, slot_origin);
        for p in 0..stack_pages {
            let err = invoke::untyped_retype(config.untyped, OBJ_FRAME, 0, stack.slot_at(p));
            if err != 0 {
                rollback_worker(desc);
                return Err(SpawnError::InvokeFailed(err));
            }
        }

        // TLS frames.
        let tls_size = tls::thread_tls_region_size();
        let tls_pages = if tls_size > 0 { tls_size / 0x1000 } else { 1 };
        let tls_slots = match alloc_consecutive_for(config, tls_pages) {
            Some(s) => s,
            None => {
                rollback_worker(desc);
                return Err(SpawnError::NoSlot);
            }
        };
        // SAFETY (within this fn's enclosing unsafe block): tls_slots..+tls_pages
        // is a fresh consecutive run from alloc_consecutive_for, owned solely by
        // this range and retyped below; slot_origin matches its source.
        let tls_range = OwnedSlotRange::from_consecutive_in(tls_slots, tls_pages, slot_origin);
        for p in 0..tls_pages {
            let err = invoke::untyped_retype(config.untyped, OBJ_FRAME, 0, tls_range.slot_at(p));
            if err != 0 {
                rollback_worker(desc);
                return Err(SpawnError::InvokeFailed(err));
            }
        }

        // Carve a VA region and map everything.
        let region_base = alloc_worker_va();
        let stack_va = region_base + 0x1000; // skip guard
        let ipc_va = stack_va + stack_pages * 0x1000;
        let tls_va = ipc_va + 0x1000;
        (*desc).stack_base = stack_va;
        (*desc).stack_size = stack_pages * 0x1000;
        (*desc).ipc_buf_vaddr = ipc_va;
        (*desc).tls_region = tls_va;
        (*desc).tls_region_size = tls_pages * 0x1000;

        for p in 0..stack_pages {
            let err = invoke::vspace_map(
                CAP_SELF_VSPACE,
                stack.borrow_at(p),
                stack_va + p * 0x1000,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                rollback_worker(desc);
                return Err(SpawnError::InvokeFailed(err));
            }
        }
        let err = invoke::vspace_map(
            CAP_SELF_VSPACE,
            ipc.borrow(),
            ipc_va,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(err));
        }
        for p in 0..tls_pages {
            let err = invoke::vspace_map(
                CAP_SELF_VSPACE,
                tls_range.borrow_at(p),
                tls_va + p * 0x1000,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                rollback_worker(desc);
                return Err(SpawnError::InvokeFailed(err));
            }
        }

        // Install TLS block.
        let (tp, tls_block) = init_worker_tls(tls_va, tls_pages * 0x1000, desc);
        (*desc).tls_ptr = tls_block;
        (*tls_block).desc = desc as *mut u8;
        (*tls_block).thread_id = (*desc).thread_id;
        trona_kernel::ipc::ipc_context_init(
            &raw mut (*tls_block).ipc_ctx,
            ipc_va as *mut uapi::kernite_ipc_buffer,
        );

        // Configure TCB: share CSpace and VSpace.
        let err = if config.cspace_depth > 0 {
            invoke::tcb_set_space_with_depth(
                tcb.borrow(),
                CAP_SELF_CSPACE,
                CAP_SELF_VSPACE,
                config.cspace_depth,
            )
        } else {
            invoke::tcb_set_space(tcb.borrow(), CAP_SELF_CSPACE, CAP_SELF_VSPACE)
        };
        if err != 0 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(err));
        }
        let err = invoke::tcb_set_ipc_buffer(tcb.borrow(), ipc_va);
        if err != 0 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(err));
        }
        let err = invoke::tcb_set_tls_base(tcb.borrow(), tp);
        if err != 0 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(err));
        }

        // Push [entry, arg, fake_ret, pad] on the new stack so the naked
        // trampoline can pop them as calling-convention arguments.
        // The 32-byte footprint keeps SP 16-byte aligned on aarch64.
        let stack_top = stack_va + stack_pages * 0x1000;
        let trampoline_rsp = stack_top - 32;
        let args = trampoline_rsp as *mut u64;
        *args = entry as *const () as u64;
        *(args.add(1)) = arg as u64;
        *(args.add(2)) = 0; // fake return address slot
        *(args.add(3)) = 0; // padding

        let err = invoke::tcb_configure(
            tcb.borrow(),
            thread_entry_trampoline as *const () as u64,
            trampoline_rsp,
            ipc_va,
        );
        if err != 0 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(err));
        }
        let err = invoke::sc_configure(sc.borrow(), budget_ns, period_ns);
        if err != 0 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(err));
        }
        let err = invoke::sc_bind(sc.borrow(), tcb.borrow());
        if err != 0 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(err));
        }
        let err = invoke::tcb_start(tcb.borrow());
        if err != 0 {
            rollback_worker(desc);
            return Err(SpawnError::InvokeFailed(err));
        }

        // Spawn fully succeeded: move the owned caps into the descriptor. Up to
        // here any failure dropped them locally (delete + free); from
        // now the thread owns them for its lifetime and `cleanup_thread`
        // releases them on reap.
        (*desc).tcb_cap = ThreadCap::Owned(tcb);
        (*desc).sc_cap = ThreadCap::Owned(sc);
        (*desc).ipc_frame_cap = ThreadCap::Owned(ipc);
        (*desc).stack_frames = Some(stack);
        (*desc).tls_frames = Some(tls_range);

        Ok(ThreadHandle {
            tcb: tcb_slot,
            sc: sc_slot,
            pool_idx,
        })
    }
}

/// Exit the calling thread. Same as `trona::syscall::thread_exit` —
/// re-exported here so callers don't need to reach into `syscall`.
#[inline]
pub fn thread_exit() -> ! {
    if let Some(tls_block) = tls::current_tls() {
        unsafe {
            let desc = tls::desc_from_tls(tls_block);
            let init_tid = (*desc).init_tid;
            (*desc).state.store(tls::TD_EXITED, Ordering::Release);
            notify_init_thread_exit(init_tid, 0);
        }
    }
    trona_kernel::syscall::thread_exit()
}

// ---------------------------------------------------------------------------
// Entry trampoline
// ---------------------------------------------------------------------------

// Assembly trampoline for spawned thread entry.
//
// Stack on entry (pushed by `spawn_fn` just before `tcb_configure`):
//   [SP+0]  = entry function pointer
//   [SP+8]  = user arg
//   [SP+16] = fake return address
//   [SP+24] = padding
//
// Pops (entry, arg) into the calling-convention registers, discards the
// fake return, and tail-calls into `thread_entry_helper`.
unsafe extern "C" {
    fn thread_entry_trampoline();
}

/// C-ABI helper called from the naked trampoline once the caller-provided
/// entry + arg have been moved into registers (`arg0 = user arg`,
/// `arg1 = entry fn`).
#[unsafe(no_mangle)]
unsafe extern "C" fn thread_entry_helper(
    arg: *mut u8,
    entry: unsafe extern "C" fn(*mut u8) -> (),
) -> ! {
    unsafe {
        // `current_ipc_ctx` and friends need the TLS-active flag.
        tls::THREAD_LOCAL_ACTIVE.store(true, Ordering::Release);
        entry(arg);
        // Entry returned — best-effort clean exit.
        thread_exit();
    }
}
