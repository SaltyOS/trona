//! POSIX threads (pthreads) implementation — thin client over init.
//!
//! Thread lifecycle (TCB / SchedContext / IPC frame allocation, kernel
//! object configuration, join/detach/exit synchronization) is owned by
//! init and exposed via the INIT_THREAD_* IPC labels. libpthread is
//! responsible only for:
//!
//! - Allocating the per-thread stack (via mmap into the caller's vspace)
//! - Computing the architecture-specific TLS layout and initializing TLS
//! - Allocating the per-thread IPC buffer mapping
//! - Issuing INIT_THREAD_CREATE / EXIT / JOIN / DETACH / LIST
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

use crate::*;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
// posix consts already in scope via lib.rs `pub use crate::consts::*`
use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::*;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::debug::serial;
use trona_runtime::thread::tls::{
    self as substrate_tls, MAX_THREADS, TD_RUNNING, TD_UNUSED, ThreadDesc, ThreadOwner,
    desc_from_tls, next_thread_id, thread_desc,
};

use crate::tls::{self, CleanupHandler, ThreadLocalBlock};

/// Default thread stack size: 2 MiB
const DEFAULT_STACK_SIZE: u64 = 2 * 1024 * 1024;

/// Hint for next free thread pool slot — avoids O(N) linear scan.
static NEXT_FREE_HINT: AtomicUsize = AtomicUsize::new(1);

#[inline]
#[cfg(target_arch = "aarch64")]
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

/// Per-thread POSIX overlay. Anchors the init-side tid, sleep / signal
/// wakeup capabilities (per-thread `EventQueue` + `Timer` + signal-pipe
/// `Watch`), and any local flags that pthread_* APIs need without
/// round-tripping to init.
pub struct PosixThreadExt {
    /// init-assigned per-process tid. 0 = main thread, >= 1 = aux.
    pub init_tid: AtomicU32,
    /// Stack mapping base address (returned by `posix_mmap`). 0 if the
    /// stack is not owned by libpthread (main thread).
    pub stack_base: AtomicU64,
    /// Stack mapping size in bytes.
    pub stack_size: AtomicU64,
    /// True once `pthread_detach` has been called from the parent side.
    /// Used by `pthread_join` to refuse joining a detached handle.
    pub detached: AtomicU32,
    /// Per-thread wakeup `EventQueue` cap (lazy-retyped on first
    /// `sleep` / `sigsuspend` / `posix_sigcheck`). `None` means not yet
    /// allocated. See `crate::wakeup`. Accessed only by the owning thread.
    pub wakeup_eq: Option<OwnedCap>,
    /// Per-thread sleep `Timer` cap. `None` means not yet allocated.
    /// Accessed only by the owning thread.
    pub sleep_timer: Option<OwnedCap>,
    /// Per-thread `Watch` cap that bridges
    /// `signal_pipe.STATE_READABLE` into this thread's `wakeup_eq`.
    /// One-shot: re-armed by the wakeup loop after each signal-pipe
    /// record is drained. Accessed only by the owning thread.
    pub signal_watch: Option<OwnedCap>,
}

// SAFETY: PosixThreadExt is accessed only by its owning thread (or by the
// joiner after the thread has exited). OwnedCap is !Send+!Sync by default,
// but single-owner discipline enforced by the pthread lifecycle makes this safe.
unsafe impl Send for PosixThreadExt {}
unsafe impl Sync for PosixThreadExt {}

impl PosixThreadExt {
    const fn zeroed() -> Self {
        PosixThreadExt {
            init_tid: AtomicU32::new(0),
            stack_base: AtomicU64::new(0),
            stack_size: AtomicU64::new(0),
            detached: AtomicU32::new(0),
            wakeup_eq: None,
            sleep_timer: None,
            signal_watch: None,
        }
    }
}

static mut POSIX_EXT_POOL: [PosixThreadExt; MAX_THREADS] =
    [const { PosixThreadExt::zeroed() }; MAX_THREADS];

/// Get a raw pointer to POSIX extension pool slot `index`.
#[inline]
pub(crate) fn ext_ptr(index: usize) -> *mut PosixThreadExt {
    unsafe {
        let base = &raw mut POSIX_EXT_POOL as *mut PosixThreadExt;
        base.add(index)
    }
}

/// Returns a raw pointer to the calling thread's POSIX extension. The
/// returned pointer is stable for the lifetime of the thread (pool
/// slot only recycled after `pthread_join` / `cleanup`); callers may
/// dereference for atomic ops without locking. Returns null before
/// TLS is active (very early CRT bring-up) so callers fall back to
/// process-global wakeup state in that window.
pub fn current_ext_ptr() -> *mut PosixThreadExt {
    let tls = match trona_runtime::thread::tls::current_tls() {
        Some(t) => t,
        None => return core::ptr::null_mut(),
    };
    let desc = unsafe { trona_runtime::thread::tls::desc_from_tls(tls) };
    if desc.is_null() {
        return core::ptr::null_mut();
    }
    let base = trona_runtime::thread::tls::thread_desc(0);
    let offset = unsafe { desc.offset_from(base) } as usize;
    if offset >= MAX_THREADS {
        return core::ptr::null_mut();
    }
    ext_ptr(offset)
}

// ---------------------------------------------------------------------------
// Constants and handle encoding
// ---------------------------------------------------------------------------

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

/// POSIX personality cleanup: called by substrate's `cleanup_thread()` before
/// the descriptor slot is recycled.
///
/// Releases the per-thread wakeup caps (`EventQueue`, `Timer`, `Watch`) that
/// live in this process's CSpace. Init reaps the kernel-object caps it
/// allocated (TCB / SC / fault MP); the wakeup caps allocated by the trona
/// POSIX library are ours to release here. This fires for detached threads
/// (INIT_THREAD_EXIT path) and any other personality-cleanup scenario.
/// Joinable threads are cleaned up in `pthread_join` before the descriptor
/// is recycled, so those caps are already `None` by the time this runs.
unsafe fn posix_personality_cleanup(desc: *mut ThreadDesc) {
    unsafe {
        let ext = (*desc).personality_data as *mut PosixThreadExt;
        if ext.is_null() {
            return;
        }
        // Drop releases each cap: cnode_delete + slot_free.
        drop((*ext).wakeup_eq.take());
        drop((*ext).sleep_timer.take());
        drop((*ext).signal_watch.take());
    }
}

/// POSIX personality fork-child reinit: called by substrate's
/// `_trona_post_fork_child()`. Re-initializes the POSIX extension pool for
/// the child (only main thread survives a fork; auxiliary threads are gone).
unsafe fn posix_personality_fork_child(desc: *mut ThreadDesc) {
    unsafe {
        // Reset main thread's POSIX ext.
        let ext = ext_ptr(0);
        (*ext).init_tid.store(0, Ordering::Relaxed);
        (*ext).stack_base.store(0, Ordering::Relaxed);
        (*ext).stack_size.store(0, Ordering::Relaxed);
        (*ext).detached.store(0, Ordering::Relaxed);
        (*desc).personality_data = ext as *mut u8;

        // Clear non-main POSIX ext slots — auxiliary threads do not survive
        // fork. The child inherits a COW copy of the parent address space,
        // so these Option<OwnedCap> values look valid but the cap slots they
        // reference are stale (the child's CSpace is a clone of the parent's
        // at fork time; auxiliary threads' EQ/Timer/Watch were never
        // transferred). Suppress Drop via forget so we do not issue bogus
        // cnode_delete calls in the child.
        for i in 1..MAX_THREADS {
            let e = ext_ptr(i);
            (*e).init_tid.store(0, Ordering::Relaxed);
            (*e).stack_base.store(0, Ordering::Relaxed);
            (*e).stack_size.store(0, Ordering::Relaxed);
            (*e).detached.store(0, Ordering::Relaxed);
            core::mem::forget((*e).wakeup_eq.take());
            core::mem::forget((*e).sleep_timer.take());
            core::mem::forget((*e).signal_watch.take());
        }

        // Reset free hint for the fresh address space.
        NEXT_FREE_HINT.store(1, Ordering::Relaxed);

        crate::signals::sig_reinit_after_fork();
        crate::wakeup::reset_after_fork();
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
        (*ext).init_tid.store(0, Ordering::Relaxed);
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
// init RPC helpers
// ---------------------------------------------------------------------------

/// Issue INIT_THREAD_CREATE. Returns the per-process init tid on success.
unsafe fn pm_thread_create_call(
    entry_pc: u64,
    entry_rsp: u64,
    reserve_top: u64,
    tls_base: u64,
    ipc_buf_vaddr: u64,
    attr_flags: u64,
    stack_base: u64,
    stack_guard_bottom: u64,
) -> Result<u32, i32> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = INIT_THREAD;
        req.length = 9;
        req.regs[0] = INIT_THREAD_SUB_CREATE;
        req.regs[1] = entry_pc;
        req.regs[2] = entry_rsp;
        req.regs[3] = tls_base;
        req.regs[4] = ipc_buf_vaddr;
        req.regs[5] = attr_flags;
        req.regs[6] = stack_base;
        req.regs[7] = stack_guard_bottom;
        req.regs[8] = reserve_top;

        let mut resp = TronaMsg::zeroed();
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(err);
        }
        if resp.label != (uapi::KERNITE_OK as u64) {
            return Err(resp.label as i32);
        }
        Ok(resp.regs[0] as u32)
    }
}

/// Issue INIT_THREAD_EXIT. Sent as a blocking Send (not NBSend) so that
/// delivery is guaranteed; init does not reply.
unsafe fn pm_thread_exit_send(tid: u32, retval: u64) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = INIT_THREAD;
        req.length = 3;
        req.regs[0] = INIT_THREAD_SUB_EXIT;
        req.regs[1] = tid as u64;
        req.regs[2] = retval;
        let _ = ipc::mp_write_ctx(
            tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const req,
        );
    }
}

/// Issue INIT_THREAD_JOIN. Blocks until the target thread has exited.
unsafe fn pm_thread_join_call(tid: u32) -> Result<u64, i32> {
    unsafe {
        loop {
            let mut req = TronaMsg::zeroed();
            req.label = INIT_THREAD;
            req.length = 2;
            req.regs[0] = INIT_THREAD_SUB_JOIN;
            req.regs[1] = tid as u64;

            let mut resp = TronaMsg::zeroed();
            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                trona_runtime::client::caps::init_ep().addr(),
                &raw const req,
                &raw mut resp,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            // No INTERRUPTED re-send: the kernel reply-wait owns resume.
            // (The loop re-polls only on WOULD_BLOCK while the thread runs.)
            if err != 0 {
                return Err(super::call_err_to_posix(err));
            }
            if resp.label == (uapi::KERNITE_ERR_WOULD_BLOCK as u64) {
                trona_kernel::syscall::yield_now();
                continue;
            }
            if resp.label != (uapi::KERNITE_OK as u64) {
                return Err(super::trona_err_to_posix(resp.label));
            }
            return Ok(resp.regs[0]);
        }
    }
}

unsafe fn pm_thread_reap_call(tid: u32) -> i32 {
    unsafe {
        loop {
            let mut req = TronaMsg::zeroed();
            req.label = INIT_THREAD;
            req.length = 2;
            req.regs[0] = INIT_THREAD_SUB_REAP;
            req.regs[1] = tid as u64;

            let mut resp = TronaMsg::zeroed();
            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                trona_runtime::client::caps::init_ep().addr(),
                &raw const req,
                &raw mut resp,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            // No INTERRUPTED re-send: the kernel reply-wait owns resume.
            // (The loop re-polls only on WOULD_BLOCK while the thread runs.)
            if err != 0 {
                return super::call_err_to_posix(err);
            }
            if resp.label != (uapi::KERNITE_OK as u64) {
                return super::trona_err_to_posix(resp.label);
            }
            return 0;
        }
    }
}

/// Issue INIT_THREAD_DETACH.
unsafe fn pm_thread_detach_call(tid: u32) -> i32 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = INIT_THREAD;
        req.length = 2;
        req.regs[0] = INIT_THREAD_SUB_DETACH;
        req.regs[1] = tid as u64;

        let mut resp = TronaMsg::zeroed();
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
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
/// then asks init (INIT_THREAD_CREATE) to allocate kernel objects, map
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
        (*ext).init_tid.store(0, Ordering::Relaxed);
        (*ext).stack_base.store(0, Ordering::Relaxed);
        (*ext).stack_size.store(0, Ordering::Relaxed);
        // Per-thread wakeup objects start unallocated; the first sleep
        // / sigsuspend / posix_sigcheck on the new thread retypes a
        // fresh `EventQueue` / `Timer` / `Watch` against its CSpace.
        // Any previous occupant of this pool slot must have already
        // dropped its caps (via pthread_join or posix_personality_cleanup),
        // so these should be None. Assign None explicitly to ensure the
        // new thread starts with a clean state regardless.
        (*ext).wakeup_eq = None;
        (*ext).sleep_timer = None;
        (*ext).signal_watch = None;
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
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_LAZY | MAP_STACK,
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
        if crate::mm::posix_prefault(prefault_base as *mut u8, 8192, PROT_READ | PROT_WRITE) != 0 {
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

        // 7. Allocate the per-thread IPC buffer in this process's
        //    own VSpace. init only configures the new TCB to point at
        //    this VA; memory ownership stays with mmsrv's normal
        //    anonymous mmap path.
        let ipc_buf = crate::mm::posix_mmap(
            ::core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        if ipc_buf == usize::MAX as *mut u8 || ipc_buf.is_null() {
            serial::serial_puts(b"[PTHREAD] ipc buffer mmap failed\n");
            crate::mm::posix_munmap(stack_addr, stack_size);
            (*desc).personality_data = ::core::ptr::null_mut();
            (*desc).state.store(TD_UNUSED, Ordering::Release);
            return -12; // ENOMEM
        }
        let ipc_buf_vaddr = ipc_buf as u64;
        (*desc).ipc_buf_vaddr = ipc_buf_vaddr;
        trona_kernel::ipc::ipc_context_init(
            &raw mut (*tls_ptr).ipc_ctx,
            ipc_buf_vaddr as *mut uapi::kernite_ipc_buffer,
        );

        // 8. Push start_fn / arg / fake_ret onto the stack so the trampoline
        //    can recover them when it begins executing.
        let user_rsp = tls_block_base & !0xF;
        let trampoline_rsp = user_rsp - 8;
        let fake_ret = trampoline_rsp as *mut u64;
        *fake_ret = 0; // No return address — trampoline calls pthread_exit.

        let stack_args = (trampoline_rsp - 16) as *mut u64;
        *(stack_args) = start_fn as u64;
        *(stack_args.add(1)) = arg as u64;

        // 9. INIT_THREAD_CREATE — init allocates kernel objects, maps the
        //    IPC frame at ipc_buf_vaddr, configures the TCB, replies with the
        //    assigned tid, and resumes the new thread after reply.
        let attr_flags: u64 = if (*ext).detached.load(Ordering::Relaxed) != 0 {
            1
        } else {
            0
        };
        // INIT_THREAD_CREATE wire distinguishes the initial SP (entry_rsp,
        // with argv / start_fn already pushed) from the reserve's exclusive
        // upper bound (stack_top). The kernel's TCB_SET_STACK_BOUNDS check
        // locates the REGION_STACK VmArea from `stack_top - PAGE_SIZE`, so
        // it has to be the exact reserve top — not the post-push entry SP,
        // which could land anywhere inside the TLS/TCB footprint and
        // therefore inside a different VmArea page.
        let reserve_top = stack_base + stack_size as u64;
        let entry_rsp = trampoline_rsp - 16;
        let create_res = pm_thread_create_call(
            pthread_entry_trampoline as *const () as u64,
            entry_rsp,
            reserve_top,
            tp,
            ipc_buf_vaddr,
            attr_flags,
            stack_base,
            0, // no guard hole tracked for pthread stacks; the region
               // below the MAP_STACK mapping is already unmapped, so
               // any overrun faults without matching a VmArea.
        );
        match create_res {
            Ok(init_tid) => {
                (*ext).init_tid.store(init_tid, Ordering::Release);
            }
            Err(e) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PTHREAD] INIT_THREAD_CREATE failed err=");
                    _lb.hex(e as u64);
                    _lb.str(b"\n");
                });
                crate::mm::posix_munmap(ipc_buf_vaddr as *mut u8, 4096);
                crate::mm::posix_munmap(stack_addr, stack_size);
                (*desc).personality_data = ::core::ptr::null_mut();
                (*desc).state.store(TD_UNUSED, Ordering::Release);
                return -12; // ENOMEM
            }
        }

        // 10. Return ABA-safe thread handle.
        if !thread_out.is_null() {
            let cur_gen = (*desc).generation.load(Ordering::Relaxed);
            *thread_out = encode_handle(slot_index, cur_gen);
        }

        0
    }
}

// Thread entry trampoline.
//
// Called with: [RSP+0] = start_fn, [RSP+8] = arg
// Pops them into RDI/RSI and tail-calls the helper.
unsafe extern "C" {
    fn pthread_entry_trampoline();
}

/// Helper called by the naked trampoline with start_fn in RDI and arg in RSI.
#[unsafe(no_mangle)]
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
        // init resumes the new TCB before pthread_create() has finished
        // publishing the assigned tid back into the shared POSIX extension.
        // Hold the thread here so an immediate return cannot race into the
        // main-thread fallback path in pthread_exit().
        if !desc.is_null() {
            let ext = (*desc).personality_data as *mut PosixThreadExt;
            if !ext.is_null() {
                for _ in 0..1024 {
                    if (*ext).init_tid.load(Ordering::Acquire) != 0 {
                        break;
                    }
                    ::core::hint::spin_loop();
                }
                while (*ext).init_tid.load(Ordering::Acquire) == 0 {
                    trona_kernel::syscall::yield_now();
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
/// Sends INIT_THREAD_EXIT to init (which records the retval and wakes any
/// joiner) and then stops making forward progress. init suspends the
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
                        let init_tid = if !ext.is_null() {
                            (*ext).init_tid.load(Ordering::Acquire)
                        } else {
                            0
                        };
                        // Main thread (pool slot 0) terminates the process.
                        let is_main_thread = matches!(desc_pool_index(desc), Some(0));
                        if is_main_thread {
                            crate::proc::posix_exit(0);
                        }
                        pm_thread_exit_send(init_tid, retval as u64);
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

        trona_kernel::syscall::thread_exit();
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

        let init_tid = (*ext).init_tid.load(Ordering::Acquire);
        if init_tid == 0 {
            return -22; // EINVAL — main thread or uninitialized
        }

        let join_res = pm_thread_join_call(init_tid);
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

        // init has reaped the kernel objects already. Acknowledge the
        // successful join so init can recycle its per-process thread slot,
        // then unmap the stack we owned and recycle the local pool slot.
        let _ = pm_thread_reap_call(init_tid);
        let stack_base = (*ext).stack_base.swap(0, Ordering::AcqRel);
        let stack_size = (*ext).stack_size.swap(0, Ordering::AcqRel);
        if stack_base != 0 && stack_size != 0 {
            crate::mm::posix_munmap(stack_base as *mut u8, stack_size);
        }
        let ipc_buf_vaddr = (*desc).ipc_buf_vaddr;
        if ipc_buf_vaddr != 0 {
            crate::mm::posix_munmap(ipc_buf_vaddr as *mut u8, 4096);
        }

        // Release the joined thread's per-thread wakeup caps. These live
        // in this process's own CSpace and are not visible to init — init
        // reaps only the TCB / SC / fault-MP caps it allocated. Dropping
        // the OwnedCap here issues cnode_delete + slot_free for each, so
        // the next occupant of this pool slot starts with None and lazy-
        // retypes its own fresh `EventQueue` / `Timer` / `Watch`.
        drop((*ext).wakeup_eq.take());
        drop((*ext).sleep_timer.take());
        drop((*ext).signal_watch.take());

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

use trona_kernel::syscall::futex_wake;

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
/// Tells init to detach the target thread; on success, marks the local
/// extension as detached so future `pthread_join` calls reject the handle
/// without round-tripping. The local stack mapping is *not* freed here —
/// the detached thread's stack is reclaimed by init at thread exit
/// time via `MM_FREE_STACK_REGION`, using the `stack_base` it recorded at
/// `INIT_THREAD_CREATE`. From userland's perspective the stack stays live
/// until the detached thread calls `pthread_exit` (or returns from its
/// start function).
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
        let init_tid = (*ext).init_tid.load(Ordering::Acquire);
        if init_tid == 0 {
            return -22; // EINVAL — main thread
        }
        let r = pm_thread_detach_call(init_tid);
        if r != (uapi::KERNITE_OK as u64) as i32 {
            return -22;
        }
        (*ext).detached.store(1, Ordering::Release);
        0
    }
}
