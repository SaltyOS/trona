//! POSIX threads (pthreads) implementation
//!
//! Provides pthread_create, pthread_join, pthread_exit, pthread_self,
//! pthread_detach, and pthread_cancel on top of SaltyOS kernel primitives
//! (TCB, SchedContext, futex, TLS).
//!
//! ## Architecture
//!
//! Thread lifecycle is split between the substrate and the POSIX personality:
//!
//! - **Substrate** (`trona::tls`): owns the `ThreadDesc` pool (64 slots),
//!   thread IDs, TLS blocks, caps, stack/IPC mappings. Personality-neutral.
//! - **POSIX** (this file): owns `PosixThreadExt` — join/detach state,
//!   exit values. Linked to the substrate desc via `desc.personality_data`.
//!
//! ## Handle lifetime safety
//!
//! `pthread_t` is an opaque u64 encoding a pool index and generation counter
//! (not a raw pointer). The generation counter is incremented each time a pool
//! slot is recycled, preventing ABA issues where a stale handle could
//! reference a different thread. All API functions validate the generation
//! and owner before accessing the pool slot.
//!
//! ## State machine
//!
//! Substrate state (ThreadDesc.state):
//! ```text
//! TD_UNUSED ──alloc──► TD_RUNNING ──exit──► TD_EXITED ──reap──► TD_REAPING ──cleanup──► TD_UNUSED
//! ```
//!
//! POSIX overlay (PosixThreadExt.detached):
//! ```text
//! joinable (false) → pthread_detach → detached (true)
//! ```
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::serial;
use trona::slot_alloc;
use trona::syscall::{futex_wait, futex_wake};
use trona::tls::{
    self as substrate_tls, ThreadDesc, ThreadOwner,
    TD_UNUSED, TD_RUNNING, TD_EXITED, TD_REAPING,
    MAX_THREADS, thread_desc, alloc_thread_desc, next_thread_id, desc_from_tls,
};
use crate::tls::{self, ThreadLocalBlock, CleanupHandler};
use trona::types::core::*;
use ::core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

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
    if align <= 1 { value } else { value & !(align - 1) }
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
// PosixThreadExt: POSIX-specific per-thread state (join/detach/exit)
// ---------------------------------------------------------------------------

/// POSIX-specific thread extension. Linked to the substrate `ThreadDesc`
/// via `desc.personality_data`.
///
/// Contains only the fields that are POSIX personality-specific and not
/// shared with other personalities (Win32, Worker).
pub struct PosixThreadExt {
    /// Futex word for pthread_join synchronization (0 = not exited, 1 = exited)
    pub join_futex: AtomicU32,
    /// Return value from pthread_exit (set by exiting thread, read by joiner)
    pub exit_value: *mut u8,
    /// Whether this thread has been detached (true = cannot be joined)
    pub detached: bool,
}

// SAFETY: PosixThreadExt fields are accessed through raw pointers with
// synchronization provided by the substrate desc's atomic state CAS.
unsafe impl Send for PosixThreadExt {}
unsafe impl Sync for PosixThreadExt {}

impl PosixThreadExt {
    const fn zeroed() -> Self {
        PosixThreadExt {
            join_futex: AtomicU32::new(0),
            exit_value: ::core::ptr::null_mut(),
            detached: false,
        }
    }

    #[inline]
    fn join_futex_ptr(&self) -> *const u32 {
        &self.join_futex as *const AtomicU32 as *const u32
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
// Rollback helper
// ---------------------------------------------------------------------------

/// Rollback helper for pthread_create failures.
///
/// Cleans up caps (if allocated), unmaps stack, and returns substrate desc slot.
///
/// # Safety
/// `desc` must be a valid substrate thread descriptor. `stack_addr`/`stack_size`
/// must be a valid mmap region (or null/0 if not yet allocated).
unsafe fn rollback_create(
    desc: *mut ThreadDesc,
    stack_addr: *mut u8,
    stack_size: u64,
    caps_allocated: bool,
) {
    unsafe {
        if caps_allocated {
            let tcb_cap = (*desc).tcb_cap;
            let sc_cap = (*desc).sc_cap;
            let frame_cap = (*desc).ipc_frame_cap;
            if tcb_cap != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, tcb_cap);
            }
            if sc_cap != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, sc_cap);
            }
            if frame_cap != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, frame_cap);
            }
        }
        if !stack_addr.is_null() && stack_size != 0 {
            crate::mm::posix_munmap(stack_addr, stack_size);
        }
        (*desc).personality_data = ::core::ptr::null_mut();
        (*desc).personality_cleanup = None;
        (*desc).state.store(TD_UNUSED, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Constants and handle encoding
// ---------------------------------------------------------------------------

/// IPC buffer mapping region: each thread gets one 4K page for its IPC buffer.
/// Start at a high address to avoid conflicts with mmap regions.
const IPC_BUF_REGION_BASE: u64 = 0x0000_7F00_0000_0000;
static IPC_BUF_NEXT: AtomicU64 = AtomicU64::new(IPC_BUF_REGION_BASE);

/// Well-known cap slots
const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_MMSRV_EP: u64 = 7;

/// Opaque thread handle: bits [15:0] = pool index, bits [31:16] = generation.
/// Prevents ABA issues where a stale handle references a recycled pool slot.
pub type PthreadT = u64;

/// Sentinel value for a null/invalid thread handle.
pub const PTHREAD_NULL: PthreadT = u64::MAX;

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

// ---------------------------------------------------------------------------
// Personality cleanup callback (registered on ThreadDesc)
// ---------------------------------------------------------------------------

/// POSIX personality cleanup: called by substrate's `cleanup_thread()`.
/// Handles POSIX-specific resource teardown before substrate cleanup.
unsafe fn posix_personality_cleanup(desc: *mut ThreadDesc) {
    unsafe {
        let tcb_cap = (*desc).tcb_cap;
        let sc_cap = (*desc).sc_cap;
        let frame_cap = (*desc).ipc_frame_cap;
        let stack_base = (*desc).stack_base;
        let stack_size = (*desc).stack_size;
        let ipc_va = (*desc).ipc_buf_vaddr;

        // Suspend the thread's TCB (should already be suspended)
        if tcb_cap != 0 {
            invoke::tcb_suspend_retry(tcb_cap, 4);
        }

        // Unmap IPC buffer page before deleting the frame cap
        if ipc_va != 0 {
            invoke::vspace_unmap(CAP_SELF_VSPACE, ipc_va);
            (*desc).ipc_buf_vaddr = 0;
        }

        // Unmap and free the stack (this also destroys the TLS block)
        if stack_base != 0 && stack_size != 0 {
            crate::mm::posix_munmap(stack_base as *mut u8, stack_size);
        }

        // Delete caps (TCB, SchedContext, IPC buffer frame)
        if tcb_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, tcb_cap);
        }
        if sc_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, sc_cap);
        }
        if frame_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, frame_cap);
        }

        // Clear POSIX extension
        (*desc).personality_data = ::core::ptr::null_mut();
    }
}

/// POSIX personality fork-child reinit: called by substrate's `_trona_post_fork_child()`.
/// Re-initializes the POSIX extension pool for the child (only main thread survives).
unsafe fn posix_personality_fork_child(desc: *mut ThreadDesc) {
    unsafe {
        // Reset main thread's POSIX ext
        let ext = ext_ptr(0);
        (*ext).join_futex.store(0, Ordering::Relaxed);
        (*ext).exit_value = ::core::ptr::null_mut();
        (*ext).detached = false;
        (*desc).personality_data = ext as *mut u8;

        // Clear non-main POSIX ext slots
        for i in 1..MAX_THREADS {
            let e = ext_ptr(i);
            (*e).join_futex.store(0, Ordering::Relaxed);
            (*e).exit_value = ::core::ptr::null_mut();
            (*e).detached = false;
        }

        // Reset free hint
        NEXT_FREE_HINT.store(1, Ordering::Relaxed);

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

        // Initialize POSIX extension for main thread (slot 0)
        let ext = ext_ptr(0);
        (*ext).join_futex.store(0, Ordering::Relaxed);
        (*ext).exit_value = ::core::ptr::null_mut();
        (*ext).detached = false;

        // Link desc ↔ POSIX ext
        (*desc).owner = ThreadOwner::Personality;
        (*desc).personality_data = ext as *mut u8;
        (*desc).personality_cleanup = Some(posix_personality_cleanup);
        (*desc).personality_fork_child = Some(posix_personality_fork_child);
    }
}

/// Compute the substrate pool index for a descriptor pointer.
fn desc_pool_index(desc: *mut ThreadDesc) -> Option<usize> {
    let base = thread_desc(0);
    let offset = unsafe { desc.offset_from(base) } as usize;
    if offset < MAX_THREADS { Some(offset) } else { None }
}

// ---------------------------------------------------------------------------
// Thread creation
// ---------------------------------------------------------------------------

/// Create a new thread.
///
/// Allocates a stack, TLS block, TCB, SchedContext, and IPC buffer frame,
/// then starts the thread running `start_fn(arg)`.
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
        // 1. Find a free slot in the substrate thread pool (slot 0 is main thread).
        // Start from NEXT_FREE_HINT to avoid O(N) scan when slots are dense.
        let hint = NEXT_FREE_HINT.load(Ordering::Relaxed);
        let mut slot_index = usize::MAX;
        for offset in 0..(MAX_THREADS - 1) {
            let i = ((hint - 1 + offset) % (MAX_THREADS - 1)) + 1;
            let desc = thread_desc(i);
            if (*desc).state.compare_exchange(
                TD_UNUSED, TD_RUNNING,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                slot_index = i;
                NEXT_FREE_HINT.store((i % (MAX_THREADS - 1)) + 1, Ordering::Relaxed);
                break;
            }
        }
        if slot_index == usize::MAX {
            // Pool full — reap detached-exited zombies and retry once.
            reap_detached_zombies();
            for i in 1..MAX_THREADS {
                let desc = thread_desc(i);
                if (*desc).state.compare_exchange(
                    TD_UNUSED, TD_RUNNING,
                    Ordering::AcqRel, Ordering::Relaxed,
                ).is_ok() {
                    slot_index = i;
                    NEXT_FREE_HINT.store((i % (MAX_THREADS - 1)) + 1, Ordering::Relaxed);
                    break;
                }
            }
        }
        if slot_index == usize::MAX {
            serial::serial_puts(b"[PTHREAD] thread pool exhausted\n");
            return -11; // EAGAIN
        }
        let desc = thread_desc(slot_index);

        // 2. Initialize POSIX extension
        let ext = ext_ptr(slot_index);
        (*ext).join_futex.store(0, Ordering::Relaxed);
        (*ext).exit_value = ::core::ptr::null_mut();

        // Determine detach state from attributes
        let detach_state = if !attr.is_null() { (*attr).detach_state } else { 0 };
        (*ext).detached = detach_state == 1;

        // Link desc → personality
        (*desc).owner = ThreadOwner::Personality;
        (*desc).personality_data = ext as *mut u8;
        (*desc).personality_cleanup = Some(posix_personality_cleanup);
        (*desc).personality_fork_child = None; // only main thread has fork callback

        // 3. Determine stack size
        let stack_size = if !attr.is_null() && (*attr).stack_size != 0 {
            ((*attr).stack_size + 4095) & !4095
        } else {
            DEFAULT_STACK_SIZE
        };

        // Map stack pages via mmsrv mmap
        let stack_addr = crate::mm::posix_mmap(
            ::core::ptr::null_mut(),
            stack_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
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

        // 4. Fill descriptor fields
        let tid = next_thread_id();
        (*desc).thread_id = tid;
        (*desc).stack_base = stack_base;
        (*desc).stack_size = stack_size;

        // 5. Place the per-thread TLS block at the top of the stack.
        let stack_top = stack_base + stack_size;
        let tls_memsz = tls::static_tls_total_memsz();
        let tls_align = ::core::cmp::max(tls::static_tls_align(), 16);
        let tcb_size = ::core::mem::size_of::<ThreadLocalBlock>() as u64;
        let runtime_tcb_align = ::core::mem::align_of::<ThreadLocalBlock>() as u64;

        #[cfg(target_arch = "x86_64")]
        let (tp, tls_block_base, tls_block_end, tls) = {
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
        let (tp, tls_block_base, tls_block_end, tls) = {
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

        ::core::ptr::write_bytes(
            tls_block_base as *mut u8,
            0,
            tls_block_end.saturating_sub(tls_block_base) as usize,
        );
        tls::initialize_static_tls_for_tp(tp);
        tls::install_runtime_tcb_anchor(tp, tls);
        (*tls).self_ptr = tls;
        (*tls).thread_id = tid;
        (*tls).desc = desc as *mut u8; // back-pointer to substrate ThreadDesc

        (*desc).tls_ptr = tls;

        // Effective stack pointer (below the entire TLS block, 16-byte aligned)
        let user_rsp = tls_block_base & !0xF;

        // 6. Allocate 3 consecutive CNode slots for TCB, SchedContext, IPC buffer frame
        let base_slot = match slot_alloc::slot_alloc_consecutive(3) {
            Some(s) => s,
            None => {
                serial::serial_puts(b"[PTHREAD] slot_alloc_consecutive(3) failed\n");
                crate::mm::posix_munmap(stack_addr, stack_size);
                (*desc).personality_data = ::core::ptr::null_mut();
                (*desc).state.store(TD_UNUSED, Ordering::Release);
                return -12; // ENOMEM
            }
        };
        let tcb_slot = base_slot;
        let sc_slot = base_slot + 1;
        let frame_slot = base_slot + 2;

        (*desc).tcb_cap = tcb_slot;
        (*desc).sc_cap = sc_slot;
        (*desc).ipc_frame_cap = frame_slot;

        // 7. Request object allocation from mmsrv
        ipc::set_receive_slot_ctx(
            tls::current_ipc_ctx(),
            CAP_SELF_CSPACE,
            tcb_slot,
            0,
        );

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_ALLOC_THREAD_OBJECTS;
        msg.length = 0;

        let err = crate::ipc_call_retry(
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[PTHREAD] MM_ALLOC_THREAD_OBJECTS failed err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            rollback_create(desc, stack_addr, stack_size, false);
            return -12; // ENOMEM
        }

        // 8. Configure TCB: share CSpace and VSpace with parent.
        // Prefer the authoritative kernel-reported depth; fall back to the
        // allocator's observed value only if the query path is unavailable.
        let depth = invoke::tcb_get_space_info(CAP_SELF_TCB)
            .unwrap_or_else(trona::slot_alloc::observed_cspace_depth);
        let err = if depth > 0 {
            invoke::tcb_set_space_with_depth(
                tcb_slot, CAP_SELF_CSPACE, CAP_SELF_VSPACE, depth as u64,
            )
        } else {
            invoke::tcb_set_space(tcb_slot, CAP_SELF_CSPACE, CAP_SELF_VSPACE)
        };
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_space failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        // 8b. Set fault handler: route VMFaults to mmsrv (same badged EP as parent)
        let err = invoke::tcb_set_fault_handler(tcb_slot, CAP_MMSRV_EP);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_fault_handler failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        // 9. Map IPC buffer frame
        let ipc_buf_vaddr = IPC_BUF_NEXT.fetch_add(4096, Ordering::Relaxed);
        (*desc).ipc_buf_vaddr = ipc_buf_vaddr;
        let err = invoke::vspace_map(
            CAP_SELF_VSPACE,
            frame_slot,
            ipc_buf_vaddr,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] IPC buffer map failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        let err = invoke::tcb_set_ipc_buffer(tcb_slot, ipc_buf_vaddr);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_ipc_buffer failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        (*tls).ipc_ctx.ipc_buffer = ipc_buf_vaddr as *mut IpcBuffer;
        (*tls).ipc_ctx.send_cap_count = 0;

        // 10. Set the architecture thread pointer for the new thread.
        let err = invoke::tcb_set_tls_base(tcb_slot, tp);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_tls_base failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        // 11. Configure entry point: trampoline pops start_fn and arg from stack
        let trampoline_rsp = user_rsp - 8;
        let fake_ret = trampoline_rsp as *mut u64;
        *fake_ret = 0; // No return address — trampoline calls pthread_exit

        let stack_args = (trampoline_rsp - 16) as *mut u64;
        *(stack_args) = start_fn as u64;
        *(stack_args.add(1)) = arg as u64;

        let err = invoke::tcb_configure(
            tcb_slot,
            pthread_entry_trampoline as *const () as u64,
            trampoline_rsp - 16,
            ipc_buf_vaddr,
        );
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_configure failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        // 12. Configure scheduling context
        let err = invoke::sc_configure(sc_slot, 10000, 100000);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] sc_configure failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        let err = invoke::sc_bind(sc_slot, tcb_slot);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] sc_bind failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        // 13. Resume the thread
        let err = invoke::tcb_resume(tcb_slot);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_resume failed\n");
            rollback_create(desc, stack_addr, stack_size, true);
            return -12; // ENOMEM
        }

        // Return ABA-safe thread handle
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
        let retval = start_fn(arg);
        pthread_exit(retval);
    }
}

/// Terminate the calling thread and store the return value.
///
/// For Personality-owned threads: transitions to TD_EXITED, wakes joiner.
/// For Worker-owned threads: transitions to TD_EXITED only (no join support).
pub unsafe fn pthread_exit(retval: *mut u8) -> ! {
    unsafe {
        let self_tcb;

        if let Some(tls) = tls::current_tls() {
            let desc = desc_from_tls(tls);
            if !desc.is_null() {
                // Read tcb_cap before any state transition — a joiner on another
                // CPU could clean up the slot as soon as we set EXITED.
                self_tcb = (*desc).tcb_cap;

                match (*desc).owner {
                    ThreadOwner::Personality => {
                        // POSIX personality: store exit value, wake joiner
                        let ext = (*desc).personality_data as *mut PosixThreadExt;
                        if !ext.is_null() {
                            (*ext).exit_value = retval;
                        }

                        // Transition: TD_RUNNING → TD_EXITED
                        let _ = (*desc).state.compare_exchange(
                            TD_RUNNING, TD_EXITED,
                            Ordering::Release, Ordering::Relaxed,
                        );

                        // Wake joiner (or detach reaper)
                        if !ext.is_null() {
                            (*ext).join_futex.store(1, Ordering::Release);
                            futex_wake((*ext).join_futex_ptr(), 1);
                        }
                    }
                    ThreadOwner::Worker => {
                        // Worker #0 (main thread as worker): process must terminate.
                        // It is the reaper anchor — no live thread remains if it exits.
                        if (*desc).thread_id == 0 {
                            unsafe { crate::proc::posix_exit(1); }
                        }
                        // Non-main worker: mark exited, substrate reaper handles cleanup.
                        let _ = (*desc).state.compare_exchange(
                            TD_RUNNING, TD_EXITED,
                            Ordering::Release, Ordering::Relaxed,
                        );
                    }
                    ThreadOwner::Main => {
                        // Main thread exit: process should terminate
                        let _ = (*desc).state.compare_exchange(
                            TD_RUNNING, TD_EXITED,
                            Ordering::Release, Ordering::Relaxed,
                        );
                    }
                }
            } else {
                self_tcb = CAP_SELF_TCB;
            }
        } else {
            self_tcb = CAP_SELF_TCB;
        }

        // Suspend self — we can't deallocate our own stack while running on it.
        // The joining thread or the process exit path handles cleanup.
        invoke::tcb_suspend_retry(self_tcb, 4);

        // Should never reach here
        loop {
            trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
    }
}

/// Clean up a POSIX thread's resources via substrate cleanup.
///
/// This calls the substrate's `cleanup_thread()` which invokes our
/// `posix_personality_cleanup` callback, then reclaims the desc slot.
///
/// # Safety
/// Caller must have successfully CAS'd the desc state to TD_REAPING.
unsafe fn cleanup_thread(desc: *mut ThreadDesc) {
    unsafe {
        substrate_tls::cleanup_thread(desc);
    }
}

/// Reclaim detached threads that have already exited.
///
/// Detached threads cannot reclaim their own stacks while running on them.
/// We check `state==TD_EXITED && ext.detached` and clean them up from
/// another live thread at pthread API entry points.
unsafe fn reap_detached_zombies() {
    unsafe {
        for i in 1..MAX_THREADS {
            let desc = thread_desc(i);
            let state = (*desc).state.load(Ordering::Acquire);
            if state != TD_EXITED {
                continue;
            }
            // Only reap if it's a POSIX Personality thread that was detached
            if (*desc).owner != ThreadOwner::Personality {
                continue;
            }
            let ext = (*desc).personality_data as *mut PosixThreadExt;
            if ext.is_null() || !(*ext).detached {
                continue;
            }
            // CAS TD_EXITED → TD_REAPING to claim for cleanup
            if (*desc).state.compare_exchange(
                TD_EXITED, TD_REAPING,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                cleanup_thread(desc);
            }
        }
    }
}

/// Process-exit sweep: reclaim already-exited thread resources.
///
/// Called from `posix_exit()` before notifying procmgr. This is a best-effort
/// final cleanup for exited thread slots that were not joined/detached-cleaned
/// yet. It only claims states that are already exited (never RUNNING).
pub unsafe fn process_exit_reap() {
    unsafe {
        for i in 1..MAX_THREADS {
            let desc = thread_desc(i);
            let state = (*desc).state.load(Ordering::Acquire);
            if state == TD_EXITED {
                if (*desc).state.compare_exchange(
                    TD_EXITED, TD_REAPING,
                    Ordering::AcqRel, Ordering::Relaxed,
                ).is_ok() {
                    cleanup_thread(desc);
                }
            }
        }
    }
}

/// Wait for a thread to terminate and retrieve its return value.
///
/// Blocks the caller until the target thread has called `pthread_exit` or
/// returned from its start function. On success, `*retval` (if non-null)
/// is set to the thread's exit value.
///
/// Returns 0 on success, negative errno on error.
pub unsafe fn pthread_join(thread: PthreadT, retval: *mut *mut u8) -> i32 {
    let (desc, index) = match unsafe { validate_handle(thread) } {
        Some(v) => v,
        None => return -3, // ESRCH — thread not found or not a Personality thread
    };

    unsafe {
        // Joining is a natural safe point to reclaim detached-exited zombies.
        reap_detached_zombies();

        // Self-join check: deadlock prevention
        if pthread_self() == thread {
            return -35; // EDEADLK
        }

        let ext = (*desc).personality_data as *mut PosixThreadExt;
        if ext.is_null() {
            return -22; // EINVAL
        }

        // Cannot join a detached thread
        if (*ext).detached {
            return -22; // EINVAL
        }

        // Wait for the thread to exit
        loop {
            let state = (*desc).state.load(Ordering::Acquire);
            if state == TD_EXITED {
                break;
            }
            if state != TD_RUNNING {
                // Thread is unused, reaping, or otherwise not joinable
                return -22; // EINVAL
            }

            // Block on the futex until the exiting thread sets join_futex=1
            let fval = (*ext).join_futex.load(Ordering::Acquire);
            if fval == 0 {
                futex_wait((*ext).join_futex_ptr(), 0);
            }
        }

        // Claim the right to reap: CAS TD_EXITED → TD_REAPING
        if (*desc).state.compare_exchange(
            TD_EXITED, TD_REAPING,
            Ordering::AcqRel, Ordering::Relaxed,
        ).is_err() {
            // Another thread already joined or detached
            return -22; // EINVAL
        }

        // Read exit value (safe: CAS Release/Acquire provides happens-before)
        if !retval.is_null() {
            *retval = (*ext).exit_value;
        }

        // Cleanup: personality + substrate resource teardown
        cleanup_thread(desc);

        0
    }
}

/// Return the calling thread's handle.
///
/// Returns an ABA-safe encoded handle for the calling thread.
pub fn pthread_self() -> PthreadT {
    match tls::current_tls() {
        Some(tls) => unsafe {
            let desc = desc_from_tls(tls);
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

/// Sentinel value for PTHREAD_CANCELED
pub const PTHREAD_CANCELED: *mut u8 = usize::MAX as *mut u8;

/// Request cancellation of a thread.
///
/// Sets the `cancel_pending` flag on the target thread's TLS. The thread
/// will be cancelled at the next cancellation point (if deferred mode).
///
/// Returns 0 on success, negative errno if the thread is not alive.
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
        let tls = (*desc).tls_ptr;
        if tls.is_null() {
            return -3; // ESRCH
        }
        // Set cancellation flag
        ::core::ptr::write_volatile(&raw mut (*tls).cancel_pending, 1);
        // Wake thread if blocked on a cancellation-point futex.
        let futex_addr = (*tls).blocked_futex_addr.load(Ordering::Acquire);
        if futex_addr != 0 {
            futex_wake(futex_addr as *const u32, 1);
        }
    }
    0
}

/// Set cancellation state (ENABLE=0, DISABLE=1).
pub unsafe fn pthread_setcancelstate(state: i32, oldstate: *mut i32) -> i32 {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            if !oldstate.is_null() {
                *oldstate = (*tls).cancel_state as i32;
            }
            (*tls).cancel_state = state as u32;
        }
        0
    } else {
        -22 // EINVAL
    }
}

/// Set cancellation type (DEFERRED=0 only).
pub unsafe fn pthread_setcanceltype(ctype: i32, oldtype: *mut i32) -> i32 {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            if !oldtype.is_null() {
                *oldtype = (*tls).cancel_type as i32;
            }
            (*tls).cancel_type = ctype as u32;
        }
        0
    } else {
        -22 // EINVAL
    }
}

/// Test for pending cancellation and act on it.
///
/// If cancellation is pending and enabled, runs all cleanup handlers
/// and calls `pthread_exit(PTHREAD_CANCELED)`.
pub unsafe fn pthread_testcancel() {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            let pending = ::core::ptr::read_volatile(&raw const (*tls).cancel_pending);
            if pending != 0 && (*tls).cancel_state == 0 {
                run_cleanup_handlers(tls);
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
    if let Some(tls) = tls::current_tls() {
        unsafe {
            (*handler).routine = routine;
            (*handler).arg = arg;
            (*handler).next = (*tls).cleanup_stack;
            (*tls).cleanup_stack = handler;
        }
    }
}

/// Pop a cleanup handler from the thread's cleanup stack.
/// If `execute` is non-zero, calls the handler's routine.
pub unsafe fn pthread_cleanup_pop_impl(execute: i32) {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            let handler = (*tls).cleanup_stack;
            if !handler.is_null() {
                (*tls).cleanup_stack = (*handler).next;
                if execute != 0 {
                    ((*handler).routine)((*handler).arg);
                }
            }
        }
    }
}

/// Run all cleanup handlers on the thread's cleanup stack (LIFO order).
unsafe fn run_cleanup_handlers(tls: *mut ThreadLocalBlock) {
    unsafe {
        loop {
            let handler = (*tls).cleanup_stack;
            if handler.is_null() {
                break;
            }
            (*tls).cleanup_stack = (*handler).next;
            ((*handler).routine)((*handler).arg);
        }
    }
}

/// Mark a thread as detached (cannot be joined).
///
/// If the thread is still running, marks it as detached.
/// If the thread already exited, performs immediate cleanup.
///
/// Returns 0 on success, negative errno on error.
pub unsafe fn pthread_detach(thread: PthreadT) -> i32 {
    let (desc, _index) = match unsafe { validate_handle(thread) } {
        Some(v) => v,
        None => return -3, // ESRCH — thread not found or not a Personality thread
    };
    unsafe {
        // Detach calls are also safe points for deferred cleanup.
        reap_detached_zombies();

        let ext = (*desc).personality_data as *mut PosixThreadExt;
        if ext.is_null() {
            return -22; // EINVAL
        }

        // Already detached
        if (*ext).detached {
            return -22; // EINVAL
        }

        let state = (*desc).state.load(Ordering::Acquire);

        if state == TD_RUNNING {
            // Thread is still running — mark as detached
            (*ext).detached = true;
            // Wake any thread blocked in pthread_join's futex_wait loop.
            (*ext).join_futex.store(1, Ordering::Release);
            futex_wake((*ext).join_futex_ptr(), 1);
            return 0;
        }

        if state == TD_EXITED {
            // Thread already exited — claim and clean up immediately
            (*ext).detached = true;
            if (*desc).state.compare_exchange(
                TD_EXITED, TD_REAPING,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                cleanup_thread(desc);
                return 0;
            }
        }

        // Already reaping, unused, or otherwise not detachable
        -22 // EINVAL
    }
}
