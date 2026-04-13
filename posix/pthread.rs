//! POSIX threads (pthreads) implementation — thin client over procmgr.
//!
//! Thread lifecycle (TCB / SchedContext / IPC frame allocation, kernel
//! object configuration, join/detach/exit synchronization) is owned by
//! procmgr and exposed via the PM_THREAD_* IPC labels. libpthread is
//! responsible only for:
//!
//! - Allocating the per-thread stack (via mmap into the caller's vspace)
//! - Computing the architecture-specific TLS layout and initializing TLS
//! - Picking the IPC buffer virtual address (which procmgr then maps)
//! - Issuing PM_THREAD_CREATE / EXIT / JOIN / DETACH / LIST
//! - Cancellation (TLS-based, no kernel objects involved)
//!
//! All retype/configure/resume calls have been removed; the substrate
//! ThreadDesc pool is still used to anchor TLS, thread identity, and the
//! cancellation flag for each personality-managed thread.
//!
//! ## Handle lifetime safety
//!
//! `pthread_t` is an opaque u64 encoding a substrate pool index and a
//! generation counter (not a raw pointer). The generation counter is
//! incremented each time a pool slot is recycled, preventing ABA issues
//! where a stale handle could reference a different thread.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::serial;
use trona::tls::{
    self as substrate_tls, desc_from_tls, next_thread_id, thread_desc, ThreadDesc, ThreadOwner,
    MAX_THREADS, TD_RUNNING, TD_UNUSED,
};
use trona::types::core::*;

use crate::tls::{self, CleanupHandler, ThreadLocalBlock};

/// Default thread stack size: 2 MiB
const DEFAULT_STACK_SIZE: u64 = 2 * 1024 * 1024;

/// Hint for next free thread pool slot — avoids O(N) linear scan.
static NEXT_FREE_HINT: AtomicUsize = AtomicUsize::new(1);

#[inline]
fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.saturating_add(align - 1) & !(align - 1)
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

/// Thread attributes for pthread_create.
#[repr(C)]
pub struct PthreadAttr {
    /// Stack size in bytes (0 = default 2 MiB)
    pub stack_size: u64,
    /// Detach state: 0 = joinable, 1 = detached
    pub detach_state: u32,
    /// Padding for alignment
    _pad: u32,
}

impl PthreadAttr {
    pub const fn default() -> Self {
        PthreadAttr {
            stack_size: 0,
            detach_state: 0,
            _pad: 0,
        }
    }

    pub const fn new(stack_size: u64, detach_state: u32) -> Self {
        PthreadAttr {
            stack_size,
            detach_state,
            _pad: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PosixThreadExt: POSIX-specific per-thread state
// ---------------------------------------------------------------------------

/// Per-thread POSIX overlay. Anchors the procmgr-side tid and any local
/// flags that pthread_* APIs need without round-tripping to procmgr.
pub struct PosixThreadExt {
    /// procmgr-assigned per-process tid. 0 = main thread, >= 1 = aux.
    pub procmgr_tid: AtomicU32,
    /// Cap slot of the TCB cap returned from PM_THREAD_CREATE (cap_transfer).
    /// Stored for completeness — pthread_cancel uses TLS futexes, not the
    /// TCB cap, but we keep the slot so the procmgr-derived cap can be
    /// dropped at join/detach time.
    pub tcb_cap: AtomicU64,
    /// Stack mapping base address (returned by `posix_mmap`). 0 if the
    /// stack is not owned by libpthread (main thread).
    pub stack_base: AtomicU64,
    /// Stack mapping size in bytes.
    pub stack_size: AtomicU64,
    /// True once `pthread_detach` has been called from the parent side.
    /// Used by `pthread_join` to refuse joining a detached handle.
    pub detached: AtomicU32,
}

// SAFETY: PosixThreadExt fields are atomics or accessed only by the owning
// thread before publication / after join.
unsafe impl Send for PosixThreadExt {}
unsafe impl Sync for PosixThreadExt {}

impl PosixThreadExt {
    const fn zeroed() -> Self {
        PosixThreadExt {
            procmgr_tid: AtomicU32::new(0),
            tcb_cap: AtomicU64::new(0),
            stack_base: AtomicU64::new(0),
            stack_size: AtomicU64::new(0),
            detached: AtomicU32::new(0),
        }
    }
}

static mut POSIX_EXT_POOL: [PosixThreadExt; MAX_THREADS] =
    [const { PosixThreadExt::zeroed() }; MAX_THREADS];

/// Get a raw pointer to POSIX extension pool slot `index`.
#[inline]
fn ext_ptr(index: usize) -> *mut PosixThreadExt {
    unsafe {
        let base = &raw mut POSIX_EXT_POOL as *mut PosixThreadExt;
        base.add(index)
    }
}

// ---------------------------------------------------------------------------
// Constants and handle encoding
// ---------------------------------------------------------------------------

/// IPC buffer mapping region: each thread gets one 4K page for its IPC buffer.
/// Start at a high address to avoid conflicts with mmap regions. The counter
/// is per-process (each child gets its own copy of this static).
const IPC_BUF_REGION_BASE: u64 = 0x0000_7F00_0000_0000;
static IPC_BUF_NEXT: AtomicU64 = AtomicU64::new(IPC_BUF_REGION_BASE);

/// Opaque thread handle: bits [15:0] = pool index, bits [31:16] = generation.
/// Prevents ABA issues where a stale handle references a recycled pool slot.
pub type PthreadT = u64;

/// Sentinel value for a null/invalid thread handle.
pub const PTHREAD_NULL: PthreadT = u64::MAX;

/// Sentinel value for PTHREAD_CANCELED
pub const PTHREAD_CANCELED: *mut u8 = usize::MAX as *mut u8;

/// Encode a pool index and generation counter into an opaque handle.
fn encode_handle(index: usize, generation: u32) -> PthreadT {
    ((index as u64) & 0xFFFF) | (((generation as u64) & 0xFFFF) << 16)
}

/// Decode a handle into (pool_index, generation). Returns None for invalid handles.
fn decode_handle(handle: PthreadT) -> Option<(usize, u16)> {
    if handle == PTHREAD_NULL {
        return None;
    }
    let index = (handle & 0xFFFF) as usize;
    let generation = ((handle >> 16) & 0xFFFF) as u16;
    if index >= MAX_THREADS {
        return None;
    }
    Some((index, generation))
}

/// Validate a handle: checks generation and that the desc is Personality-owned.
/// Returns (desc pointer, pool index) if valid.
///
/// # Safety
/// The returned pointer is valid as long as the pool slot is not recycled.
unsafe fn validate_handle(handle: PthreadT) -> Option<(*mut ThreadDesc, usize)> {
    let (index, expected_gen) = decode_handle(handle)?;
    let desc = thread_desc(index);
    unsafe {
        let current_gen = (*desc).generation.load(Ordering::Acquire);
        if (current_gen as u16) != expected_gen {
            return None;
        }
        // Only POSIX personality threads are valid pthread targets
        if (*desc).owner != ThreadOwner::Personality {
            return None;
        }
        Some((desc, index))
    }
}

/// Compute the substrate pool index for a descriptor pointer.
fn desc_pool_index(desc: *mut ThreadDesc) -> Option<usize> {
    let base = thread_desc(0);
    let offset = unsafe { desc.offset_from(base) } as usize;
    if offset < MAX_THREADS {
        Some(offset)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Personality cleanup callback (registered on ThreadDesc)
// ---------------------------------------------------------------------------

/// POSIX personality cleanup: called by substrate's `cleanup_thread()` only
/// for substrate-owned threads (workers). Personality-managed threads are
/// torn down via PM_THREAD_JOIN / PM_THREAD_EXIT, so this callback is a
/// no-op for them — but we register it so a substrate-side iteration over
/// the pool does not crash on a missing callback.
unsafe fn posix_personality_cleanup(_desc: *mut ThreadDesc) {}

/// POSIX personality fork-child reinit: called by substrate's
/// `_trona_post_fork_child()`. Re-initializes the POSIX extension pool for
/// the child (only main thread survives a fork; auxiliary threads are gone).
unsafe fn posix_personality_fork_child(desc: *mut ThreadDesc) {
    unsafe {
        // Reset main thread's POSIX ext.
        let ext = ext_ptr(0);
        (*ext).procmgr_tid.store(0, Ordering::Relaxed);
        (*ext).tcb_cap.store(0, Ordering::Relaxed);
        (*ext).stack_base.store(0, Ordering::Relaxed);
        (*ext).stack_size.store(0, Ordering::Relaxed);
        (*ext).detached.store(0, Ordering::Relaxed);
        (*desc).personality_data = ext as *mut u8;

        // Clear non-main POSIX ext slots — auxiliary threads do not survive
        // fork, so the kernel objects in the child's vspace are gone too.
        for i in 1..MAX_THREADS {
            let e = ext_ptr(i);
            (*e).procmgr_tid.store(0, Ordering::Relaxed);
            (*e).tcb_cap.store(0, Ordering::Relaxed);
            (*e).stack_base.store(0, Ordering::Relaxed);
            (*e).stack_size.store(0, Ordering::Relaxed);
            (*e).detached.store(0, Ordering::Relaxed);
        }

        // Reset free hint and IPC buffer counter for the fresh address space.
        NEXT_FREE_HINT.store(1, Ordering::Relaxed);
        IPC_BUF_NEXT.store(IPC_BUF_REGION_BASE, Ordering::Relaxed);

        crate::signals::sig_reinit_after_fork();
    }
}

// ---------------------------------------------------------------------------
// Main thread initialization
// ---------------------------------------------------------------------------

/// Initialize the main thread's POSIX personality state.
///
/// Called from `tls::init_main_thread_tls()` after substrate TLS init.
/// Sets up the POSIX extension for slot 0 and registers personality
/// callbacks on the main thread's substrate descriptor.
///
/// # Safety
/// Must be called exactly once, after the main thread's TLS block is set up.
pub unsafe fn init_main_thread_control(tls: *mut ThreadLocalBlock) {
    unsafe {
        let desc = desc_from_tls(tls);
        if desc.is_null() {
            return;
        }

        // Initialize POSIX extension for main thread (slot 0).
        let ext = ext_ptr(0);
        (*ext).procmgr_tid.store(0, Ordering::Relaxed);
        (*ext).tcb_cap.store(0, Ordering::Relaxed);
        (*ext).stack_base.store(0, Ordering::Relaxed);
        (*ext).stack_size.store(0, Ordering::Relaxed);
        (*ext).detached.store(0, Ordering::Relaxed);

        // Link desc ↔ POSIX ext.
        (*desc).owner = ThreadOwner::Personality;
        (*desc).personality_data = ext as *mut u8;
        (*desc).personality_cleanup = Some(posix_personality_cleanup);
        (*desc).personality_fork_child = Some(posix_personality_fork_child);
    }
}

// ---------------------------------------------------------------------------
// procmgr RPC helpers
// ---------------------------------------------------------------------------

/// Issue PM_THREAD_CREATE. Returns `(tid, tcb_cap_slot)` on success.
///
/// `tcb_recv_slot` must be a free CSpace slot in the caller's CNode where
/// the procmgr-derived TCB cap will be deposited via cap_transfer.
unsafe fn pm_thread_create_call(
    entry_pc: u64,
    stack_top: u64,
    tls_base: u64,
    ipc_buf_vaddr: u64,
    attr_flags: u64,
    tcb_recv_slot: Cap,
) -> Result<(u32, Cap), i32> {
    unsafe {
        ipc::set_receive_slot_ctx(tls::current_ipc_ctx(), CAP_SELF_CSPACE, tcb_recv_slot, 0);

        let mut req = TronaMsg::zeroed();
        req.label = PM_THREAD_CREATE;
        req.length = 5;
        req.regs[0] = entry_pc;
        req.regs[1] = stack_top;
        req.regs[2] = tls_base;
        req.regs[3] = ipc_buf_vaddr;
        req.regs[4] = attr_flags;

        let mut resp = TronaMsg::zeroed();
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const req, &raw mut resp);
        if err != 0 {
            return Err(err);
        }
        if resp.label != TRONA_OK {
            return Err(resp.label as i32);
        }
        Ok((resp.regs[0] as u32, tcb_recv_slot))
    }
}

/// Issue PM_THREAD_EXIT. Sent as a blocking Send (not NBSend) so that
/// delivery is guaranteed; procmgr does not reply.
unsafe fn pm_thread_exit_send(tid: u32, retval: u64) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = PM_THREAD_EXIT;
        req.length = 2;
        req.regs[0] = tid as u64;
        req.regs[1] = retval;
        let _ = ipc::send_ctx(
            tls::current_ipc_ctx(),
            trona::caps::procmgr_ep(),
            &raw const req,
        );
    }
}

/// Issue PM_THREAD_JOIN. Blocks until the target thread has exited.
unsafe fn pm_thread_join_call(tid: u32) -> Result<u64, i32> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = PM_THREAD_JOIN;
        req.length = 1;
        req.regs[0] = tid as u64;

        let mut resp = TronaMsg::zeroed();
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const req, &raw mut resp);
        if err != 0 {
            return Err(err);
        }
        if resp.label != TRONA_OK {
            return Err(resp.label as i32);
        }
        Ok(resp.regs[0])
    }
}

/// Issue PM_THREAD_DETACH.
unsafe fn pm_thread_detach_call(tid: u32) -> i32 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = PM_THREAD_DETACH;
        req.length = 1;
        req.regs[0] = tid as u64;

        let mut resp = TronaMsg::zeroed();
        let err = crate::ipc_call_retry(trona::caps::procmgr_ep(), &raw const req, &raw mut resp);
        if err != 0 {
            return err;
        }
        resp.label as i32
    }
}

// ---------------------------------------------------------------------------
// Thread creation
// ---------------------------------------------------------------------------

/// Create a new thread.
///
/// Allocates a stack, sets up the TLS block, picks an IPC buffer address,
/// then asks procmgr (PM_THREAD_CREATE) to allocate kernel objects, map
/// the IPC frame into this process's vspace, and resume the new thread
/// running `start_fn(arg)`.
///
/// If `attr` is non-null, uses the specified stack size and detach state.
///
/// Returns 0 on success, negative errno on failure.
/// On success, `*thread_out` is set to the thread handle.
pub unsafe fn pthread_create(
    thread_out: *mut PthreadT,
    attr: *const PthreadAttr,
    start_fn: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> i32 {
    unsafe {
        // 1. Find a free slot in the substrate thread pool (slot 0 is main).
        let hint = NEXT_FREE_HINT.load(Ordering::Relaxed);
        let mut slot_index = usize::MAX;
        for offset in 0..(MAX_THREADS - 1) {
            let i = ((hint - 1 + offset) % (MAX_THREADS - 1)) + 1;
            let desc = thread_desc(i);
            if (*desc)
                .state
                .compare_exchange(TD_UNUSED, TD_RUNNING, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                slot_index = i;
                NEXT_FREE_HINT.store((i % (MAX_THREADS - 1)) + 1, Ordering::Relaxed);
                break;
            }
        }
        if slot_index == usize::MAX {
            serial::serial_puts(b"[PTHREAD] thread pool exhausted\n");
            return -11; // EAGAIN
        }
        let desc = thread_desc(slot_index);

        // 2. Initialize POSIX extension.
        let ext = ext_ptr(slot_index);
        (*ext).procmgr_tid.store(0, Ordering::Relaxed);
        (*ext).tcb_cap.store(0, Ordering::Relaxed);
        (*ext).stack_base.store(0, Ordering::Relaxed);
        (*ext).stack_size.store(0, Ordering::Relaxed);
        let detach_state = if !attr.is_null() {
            (*attr).detach_state
        } else {
            0
        };
        (*ext).detached.store(detach_state, Ordering::Relaxed);

        // Link desc → personality.
        (*desc).owner = ThreadOwner::Personality;
        (*desc).personality_data = ext as *mut u8;
        (*desc).personality_cleanup = Some(posix_personality_cleanup);
        (*desc).personality_fork_child = None;

        // 3. Determine stack size.
        let stack_size = if !attr.is_null() && (*attr).stack_size != 0 {
            ((*attr).stack_size + 4095) & !4095
        } else {
            DEFAULT_STACK_SIZE
        };

        // 4. Reserve the full stack VA range up front, but let mmsrv commit
        // pages lazily on demand so large default stacks do not eagerly consume
        // physical memory before the thread actually touches them.
        let stack_addr = crate::mm::posix_mmap(
            ::core::ptr::null_mut(),
            stack_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_LAZY,
            -1,
            0,
        );
        if stack_addr == usize::MAX as *mut u8 || stack_addr.is_null() {
            serial::serial_puts(b"[PTHREAD] stack mmap failed\n");
            (*desc).personality_data = ::core::ptr::null_mut();
            (*desc).state.store(TD_UNUSED, Ordering::Release);
            return -12; // ENOMEM
        }
        let stack_base = stack_addr as u64;
        (*ext).stack_base.store(stack_base, Ordering::Relaxed);
        (*ext).stack_size.store(stack_size, Ordering::Relaxed);

        // 5. Fill descriptor fields used by pthread_self / cancellation.
        let tid = next_thread_id();
        (*desc).thread_id = tid;
        (*desc).stack_base = stack_base;
        (*desc).stack_size = stack_size;

        // 6. Place the per-thread TLS block at the top of the stack.
        let stack_top = stack_base + stack_size;
        let tls_memsz = tls::static_tls_total_memsz();
        let tls_align = ::core::cmp::max(tls::static_tls_align(), 16);
        let tcb_size = ::core::mem::size_of::<ThreadLocalBlock>() as u64;
        let runtime_tcb_align = ::core::mem::align_of::<ThreadLocalBlock>() as u64;

        #[cfg(target_arch = "x86_64")]
        let (tp, tls_block_base, tls_block_end, tls_ptr) = {
            let tcb_addr = align_down(
                stack_top.saturating_sub(tcb_size),
                ::core::cmp::max(tls_align, runtime_tcb_align),
            );
            let tls_block_base = tcb_addr.saturating_sub(tls_memsz);
            (
                tcb_addr,
                tls_block_base,
                tcb_addr.saturating_add(tcb_size),
                tcb_addr as *mut ThreadLocalBlock,
            )
        };

        #[cfg(target_arch = "aarch64")]
        let (tp, tls_block_base, tls_block_end, tls_ptr) = {
            let abi_size = tls::abi_tcb_size();
            let total_hint = abi_size
                .saturating_add(tls_memsz)
                .saturating_add(runtime_tcb_align.saturating_sub(1))
                .saturating_add(tcb_size);
            let tp = align_down(stack_top.saturating_sub(total_hint), tls_align);
            let tcb_addr = align_up(
                tp.saturating_add(abi_size).saturating_add(tls_memsz),
                runtime_tcb_align,
            );
            (
                tp,
                tp,
                tcb_addr.saturating_add(tcb_size),
                tcb_addr as *mut ThreadLocalBlock,
            )
        };

        let prefault_base = (stack_top.saturating_sub(8192)) & !0xFFFu64;
        if crate::mm::posix_prefault(
            prefault_base as *mut u8,
            8192,
            PROT_READ | PROT_WRITE,
        ) != 0
        {
            serial::serial_puts(b"[PTHREAD] stack prefault failed\n");
            crate::mm::posix_munmap(stack_addr, stack_size);
            (*desc).personality_data = ::core::ptr::null_mut();
            (*desc).state.store(TD_UNUSED, Ordering::Release);
            return -12; // ENOMEM
        }

        ::core::ptr::write_bytes(
            tls_block_base as *mut u8,
            0,
            tls_block_end.saturating_sub(tls_block_base) as usize,
        );
        tls::initialize_static_tls_for_tp(tp);
        tls::install_runtime_tcb_anchor(tp, tls_ptr);
        (*tls_ptr).self_ptr = tls_ptr;
        (*tls_ptr).thread_id = tid;
        (*tls_ptr).desc = desc as *mut u8;

        (*desc).tls_ptr = tls_ptr;

        // 7. Pick the IPC buffer address. Per-process counter (each forked
        //    process gets its own copy of this static).
        let ipc_buf_vaddr = IPC_BUF_NEXT.fetch_add(4096, Ordering::Relaxed);
        (*desc).ipc_buf_vaddr = ipc_buf_vaddr;
        (*tls_ptr).ipc_ctx.ipc_buffer = ipc_buf_vaddr as *mut IpcBuffer;
        (*tls_ptr).ipc_ctx.send_cap_count = 0;

        // 8. Push start_fn / arg / fake_ret onto the stack so the trampoline
        //    can recover them when it begins executing.
        let user_rsp = tls_block_base & !0xF;
        let trampoline_rsp = user_rsp - 8;
        let fake_ret = trampoline_rsp as *mut u64;
        *fake_ret = 0; // No return address — trampoline calls pthread_exit.

        let stack_args = (trampoline_rsp - 16) as *mut u64;
        *(stack_args) = start_fn as u64;
        *(stack_args.add(1)) = arg as u64;

        // 9. Allocate a CSpace slot to receive the procmgr-derived TCB cap.
        let tcb_recv_slot = match trona::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                serial::serial_puts(b"[PTHREAD] slot_alloc for tcb recv failed\n");
                crate::mm::posix_munmap(stack_addr, stack_size);
                (*desc).personality_data = ::core::ptr::null_mut();
                (*desc).state.store(TD_UNUSED, Ordering::Release);
                return -12; // ENOMEM
            }
        };

        // 10. PM_THREAD_CREATE — procmgr allocates kernel objects, maps the
        //     IPC frame at ipc_buf_vaddr, configures the TCB, replies with the
        //     assigned tid/TCB cap, and resumes the new thread after reply.
        let attr_flags: u64 = if (*ext).detached.load(Ordering::Relaxed) != 0 {
            1
        } else {
            0
        };
        let create_res = pm_thread_create_call(
            pthread_entry_trampoline as *const () as u64,
            trampoline_rsp - 16,
            tp,
            ipc_buf_vaddr,
            attr_flags,
            tcb_recv_slot,
        );
        match create_res {
            Ok((procmgr_tid, tcb_cap)) => {
                (*ext).procmgr_tid.store(procmgr_tid, Ordering::Release);
                (*ext).tcb_cap.store(tcb_cap, Ordering::Release);
            }
            Err(e) => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PTHREAD] PM_THREAD_CREATE failed err=");
                    _lb.hex(e as u64);
                    _lb.str(b"\n");
                });
                let _ = invoke::cnode_delete(CAP_SELF_CSPACE, tcb_recv_slot);
                let _ = trona::slot_alloc::slot_free(tcb_recv_slot);
                crate::mm::posix_munmap(stack_addr, stack_size);
                (*desc).personality_data = ::core::ptr::null_mut();
                (*desc).state.store(TD_UNUSED, Ordering::Release);
                return -12; // ENOMEM
            }
        }

        // 11. Return ABA-safe thread handle.
        if !thread_out.is_null() {
            let cur_gen = (*desc).generation.load(Ordering::Relaxed);
            *thread_out = encode_handle(slot_index, cur_gen);
        }

        0
    }
}

/// Thread entry trampoline (naked — no compiler prologue).
///
/// Called with: [RSP+0] = start_fn, [RSP+8] = arg
/// Pops them into RDI/RSI and tail-calls the helper.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn pthread_entry_trampoline() {
    #[cfg(target_arch = "x86_64")]
    ::core::arch::naked_asm!(
        "pop rdi",
        "pop rsi",
        "jmp {helper}",
        helper = sym pthread_trampoline_helper,
    );
    #[cfg(target_arch = "aarch64")]
    ::core::arch::naked_asm!(
        "ldp x0, x1, [sp], #16",
        "b {helper}",
        helper = sym pthread_trampoline_helper,
    );
}

/// Helper called by the naked trampoline with start_fn in RDI and arg in RSI.
unsafe extern "C" fn pthread_trampoline_helper(
    start_fn: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> ! {
    unsafe {
        let tls_ptr = tls::current_tls().unwrap_or(::core::ptr::null_mut());
        let desc = if tls_ptr.is_null() {
            ::core::ptr::null_mut()
        } else {
            desc_from_tls(tls_ptr)
        };
        // procmgr resumes the new TCB before pthread_create() has finished
        // publishing the assigned tid back into the shared POSIX extension.
        // Hold the thread here so an immediate return cannot race into the
        // main-thread fallback path in pthread_exit().
        if !desc.is_null() {
            let ext = (*desc).personality_data as *mut PosixThreadExt;
            if !ext.is_null() {
                for _ in 0..1024 {
                    if (*ext).procmgr_tid.load(Ordering::Acquire) != 0 {
                        break;
                    }
                    ::core::hint::spin_loop();
                }
                while (*ext).procmgr_tid.load(Ordering::Acquire) == 0 {
                    trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
                }
            }
        }

        let retval = start_fn(arg);
        pthread_exit(retval);
    }
}

// ---------------------------------------------------------------------------
// pthread_exit
// ---------------------------------------------------------------------------

/// Terminate the calling thread and store the return value.
///
/// Sends PM_THREAD_EXIT to procmgr (which records the retval and wakes any
/// joiner) and then stops making forward progress. procmgr suspends the
/// auxiliary thread via its own local TCB cap before wake/reap. This avoids
/// relying on `CAP_SELF_TCB`, which always names the process's main thread in
/// a shared per-process CSpace.
pub unsafe fn pthread_exit(retval: *mut u8) -> ! {
    unsafe {
        if let Some(tls_ptr) = tls::current_tls() {
            let desc = desc_from_tls(tls_ptr);
            if !desc.is_null() {
                match (*desc).owner {
                    ThreadOwner::Personality => {
                        let ext = (*desc).personality_data as *mut PosixThreadExt;
                        let procmgr_tid = if !ext.is_null() {
                            (*ext).procmgr_tid.load(Ordering::Acquire)
                        } else {
                            0
                        };
                        // Main thread (pool slot 0) terminates the process.
                        let is_main_thread = matches!(desc_pool_index(desc), Some(0));
                        if is_main_thread {
                            crate::proc::posix_exit(0);
                        }
                        pm_thread_exit_send(procmgr_tid, retval as u64);
                    }
                    ThreadOwner::Worker => {
                        // Worker #0 (main thread as worker): process must terminate.
                        if (*desc).thread_id == 0 {
                            crate::proc::posix_exit(1);
                        }
                        // Non-main worker: substrate handles cleanup.
                        let _ = (*desc).state.compare_exchange(
                            TD_RUNNING,
                            substrate_tls::TD_EXITED,
                            Ordering::Release,
                            Ordering::Relaxed,
                        );
                    }
                    ThreadOwner::Main => {
                        crate::proc::posix_exit(0);
                    }
                }
            }
        }

        trona::syscall::thread_exit();
    }
}

// ---------------------------------------------------------------------------
// pthread_join
// ---------------------------------------------------------------------------

/// Wait for a thread to terminate and retrieve its return value.
///
/// Blocks the caller until the target thread has called `pthread_exit` or
/// returned from its start function. On success, `*retval` (if non-null)
/// is set to the thread's exit value.
///
/// Returns 0 on success, negative errno on error.
pub unsafe fn pthread_join(thread: PthreadT, retval: *mut *mut u8) -> i32 {
    let (desc, _index) = match unsafe { validate_handle(thread) } {
        Some(v) => v,
        None => return -3, // ESRCH
    };

    unsafe {
        // Self-join check: deadlock prevention.
        if pthread_self() == thread {
            return -35; // EDEADLK
        }

        let ext = (*desc).personality_data as *mut PosixThreadExt;
        if ext.is_null() {
            return -22; // EINVAL
        }
        if (*ext).detached.load(Ordering::Acquire) != 0 {
            return -22; // EINVAL
        }

        let procmgr_tid = (*ext).procmgr_tid.load(Ordering::Acquire);
        if procmgr_tid == 0 {
            return -22; // EINVAL — main thread or uninitialized
        }

        let join_res = pm_thread_join_call(procmgr_tid);
        match join_res {
            Ok(rv) => {
                if !retval.is_null() {
                    *retval = rv as *mut u8;
                }
            }
            Err(e) => {
                return e;
            }
        }

        // procmgr has reaped the kernel objects already. Drop our local
        // copy of the TCB cap, unmap the stack we owned, and recycle the
        // pool slot.
        let tcb_local = (*ext).tcb_cap.swap(0, Ordering::AcqRel);
        if tcb_local != 0 {
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, tcb_local);
            let _ = trona::slot_alloc::slot_free(tcb_local);
        }
        let stack_base = (*ext).stack_base.swap(0, Ordering::AcqRel);
        let stack_size = (*ext).stack_size.swap(0, Ordering::AcqRel);
        if stack_base != 0 && stack_size != 0 {
            crate::mm::posix_munmap(stack_base as *mut u8, stack_size);
        }

        (*desc).personality_data = ::core::ptr::null_mut();
        (*desc).personality_cleanup = None;
        (*desc).tls_ptr = ::core::ptr::null_mut();
        (*desc).stack_base = 0;
        (*desc).stack_size = 0;
        (*desc).ipc_buf_vaddr = 0;
        (*desc).generation.fetch_add(1, Ordering::Release);
        (*desc).state.store(TD_UNUSED, Ordering::Release);
        0
    }
}

// ---------------------------------------------------------------------------
// pthread_self
// ---------------------------------------------------------------------------

/// Return the calling thread's handle.
pub fn pthread_self() -> PthreadT {
    match tls::current_tls() {
        Some(tls_ptr) => unsafe {
            let desc = desc_from_tls(tls_ptr);
            if desc.is_null() {
                return PTHREAD_NULL;
            }
            match desc_pool_index(desc) {
                Some(index) => {
                    let cur_gen = (*desc).generation.load(Ordering::Relaxed);
                    encode_handle(index, cur_gen)
                }
                None => PTHREAD_NULL,
            }
        },
        None => PTHREAD_NULL,
    }
}

// ---------------------------------------------------------------------------
// pthread_cancel and friends
// ---------------------------------------------------------------------------

use trona::syscall::futex_wake;

/// Request cancellation of a thread.
///
/// Sets the `cancel_pending` flag on the target thread's TLS. The thread
/// will be cancelled at the next cancellation point (if deferred mode).
pub unsafe fn pthread_cancel(thread: PthreadT) -> i32 {
    let (desc, _index) = match unsafe { validate_handle(thread) } {
        Some(v) => v,
        None => return -3, // ESRCH
    };
    unsafe {
        let state = (*desc).state.load(Ordering::Acquire);
        if state != TD_RUNNING {
            return -3; // ESRCH
        }
        let tls_ptr = (*desc).tls_ptr;
        if tls_ptr.is_null() {
            return -3; // ESRCH
        }
        ::core::ptr::write_volatile(&raw mut (*tls_ptr).cancel_pending, 1);
        let futex_addr = (*tls_ptr).blocked_futex_addr.load(Ordering::Acquire);
        if futex_addr != 0 {
            futex_wake(futex_addr as *const u32, 1);
        }
    }
    0
}

/// Set cancellation state (ENABLE=0, DISABLE=1).
pub unsafe fn pthread_setcancelstate(state: i32, oldstate: *mut i32) -> i32 {
    if let Some(tls_ptr) = tls::current_tls() {
        unsafe {
            if !oldstate.is_null() {
                *oldstate = (*tls_ptr).cancel_state as i32;
            }
            (*tls_ptr).cancel_state = state as u32;
        }
        0
    } else {
        -22 // EINVAL
    }
}

/// Set cancellation type (DEFERRED=0 only).
pub unsafe fn pthread_setcanceltype(ctype: i32, oldtype: *mut i32) -> i32 {
    if let Some(tls_ptr) = tls::current_tls() {
        unsafe {
            if !oldtype.is_null() {
                *oldtype = (*tls_ptr).cancel_type as i32;
            }
            (*tls_ptr).cancel_type = ctype as u32;
        }
        0
    } else {
        -22 // EINVAL
    }
}

/// Test for pending cancellation and act on it.
pub unsafe fn pthread_testcancel() {
    if let Some(tls_ptr) = tls::current_tls() {
        unsafe {
            let pending = ::core::ptr::read_volatile(&raw const (*tls_ptr).cancel_pending);
            if pending != 0 && (*tls_ptr).cancel_state == 0 {
                run_cleanup_handlers(tls_ptr);
                pthread_exit(PTHREAD_CANCELED);
            }
        }
    }
}

/// Push a cleanup handler onto the thread's cleanup stack.
pub unsafe fn pthread_cleanup_push_impl(
    routine: unsafe extern "C" fn(*mut u8),
    arg: *mut u8,
    handler: *mut CleanupHandler,
) {
    if let Some(tls_ptr) = tls::current_tls() {
        unsafe {
            (*handler).routine = routine;
            (*handler).arg = arg;
            (*handler).next = (*tls_ptr).cleanup_stack;
            (*tls_ptr).cleanup_stack = handler;
        }
    }
}

/// Pop a cleanup handler from the thread's cleanup stack.
pub unsafe fn pthread_cleanup_pop_impl(execute: i32) {
    if let Some(tls_ptr) = tls::current_tls() {
        unsafe {
            let handler = (*tls_ptr).cleanup_stack;
            if !handler.is_null() {
                (*tls_ptr).cleanup_stack = (*handler).next;
                if execute != 0 {
                    ((*handler).routine)((*handler).arg);
                }
            }
        }
    }
}

unsafe fn run_cleanup_handlers(tls_ptr: *mut ThreadLocalBlock) {
    unsafe {
        loop {
            let handler = (*tls_ptr).cleanup_stack;
            if handler.is_null() {
                break;
            }
            (*tls_ptr).cleanup_stack = (*handler).next;
            ((*handler).routine)((*handler).arg);
        }
    }
}

// ---------------------------------------------------------------------------
// pthread_detach
// ---------------------------------------------------------------------------

/// Mark a thread as detached (cannot be joined).
///
/// Tells procmgr to detach the target thread; on success, marks the local
/// extension as detached so future `pthread_join` calls reject the handle
/// without round-tripping. The local stack mapping is *not* freed here —
/// detached threads leave their stack mapped until process exit.
pub unsafe fn pthread_detach(thread: PthreadT) -> i32 {
    let (desc, _index) = match unsafe { validate_handle(thread) } {
        Some(v) => v,
        None => return -3, // ESRCH
    };
    unsafe {
        let ext = (*desc).personality_data as *mut PosixThreadExt;
        if ext.is_null() {
            return -22; // EINVAL
        }
        if (*ext).detached.load(Ordering::Acquire) != 0 {
            return -22; // EINVAL — already detached
        }
        let procmgr_tid = (*ext).procmgr_tid.load(Ordering::Acquire);
        if procmgr_tid == 0 {
            return -22; // EINVAL — main thread
        }
        let r = pm_thread_detach_call(procmgr_tid);
        if r != TRONA_OK as i32 {
            return -22;
        }
        (*ext).detached.store(1, Ordering::Release);
        0
    }
}
