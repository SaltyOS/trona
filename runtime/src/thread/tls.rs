//! Substrate thread-local storage and thread descriptor management.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! This module owns all thread infrastructure: TLS block layout, thread pool,
//! static TLS initialization, TP register management, and thread identity.
//! Personalities (POSIX, Win32) extend threads via `ThreadDesc.personality_data`.
//!
//! # Architecture
//!
//! ```text
//! substrate/tls.rs (this file)
//!   ThreadDesc pool, TLS init, TP management, current_tls(), post_fork_child()
//!
//!       extends via personality_data + owner
//!         ┌──────┴──────┐
//!    posix/pthread.rs  win32/thread.rs
//!    PosixThreadExt    Win32ThreadExt
//! ```
//!
//! # Worker threads
//!
//! Worker threads created by `substrate/worker.rs` are first-class threads in
//! this pool with full TLS (IPC context, thread_id, errno). They use
//! `ThreadOwner::Worker`. Worker handlers should NOT call `pthread_exit`.
//! If worker #0 (main thread) reaches `pthread_exit`, the process terminates.

use super::cap::{OwnedSlotRange, ThreadCap};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;

const CAP_SELF_TCB: CapRef = CapRef::flat(uapi::KERNITE_CAP_SELF_TCB as u64);
const CAP_SELF_VSPACE: CapRef = CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64);

// ---------------------------------------------------------------------------
// ThreadDesc — personality-neutral thread descriptor (Rust internal, not C ABI)
// ---------------------------------------------------------------------------

/// Maximum concurrent threads per process (same as pthread MAX_THREADS).
pub const MAX_THREADS: usize = 64;

/// Thread descriptor state constants.
pub const TD_UNUSED: u32 = 0;
pub const TD_RUNNING: u32 = 1;
pub const TD_EXITED: u32 = 2;
pub const TD_REAPING: u32 = 3;

/// Personality-specific cleanup function.
/// Called by `cleanup_thread()` before substrate resource cleanup.
/// The function receives the descriptor of a non-running thread.
pub type PersonalityCleanupFn = unsafe fn(desc: *mut ThreadDesc);

/// Personality-specific fork-child reinit function.
/// Called by `post_fork_child()` on the main thread's descriptor in the child.
pub type PersonalityForkChildFn = unsafe fn(desc: *mut ThreadDesc);

/// Thread ownership — determines who handles resource cleanup.
#[derive(Clone, Copy, PartialEq)]
pub enum ThreadOwner {
    /// Main thread — lives for the lifetime of the process.
    Main,
    /// Worker pool thread — substrate handles resource cleanup.
    Worker,
    /// Personality-managed thread (pthread_create, CreateThread, etc.) —
    /// personality handles resource cleanup.
    Personality,
}

/// Per-thread descriptor. Owned by the substrate thread pool.
///
/// This is a Rust-internal type, NOT exposed to the C ABI surface.
/// Personalities access it through the opaque `ThreadLocalBlock.desc` pointer.
pub struct ThreadDesc {
    /// Lifecycle state (TD_UNUSED / TD_RUNNING / TD_EXITED / TD_REAPING)
    pub state: AtomicU32,
    /// Generation counter — incremented on each slot reuse to prevent ABA.
    pub generation: AtomicU32,

    /// The thread's TCB capability — `Owned` for a spawned worker, the
    /// borrowed `CAP_SELF_TCB` for the main thread, `None` for an
    /// mmsrv-backed worker (its objects live in init's CSpace).
    pub(crate) tcb_cap: ThreadCap,
    /// The thread's SchedContext capability.
    pub(crate) sc_cap: ThreadCap,
    /// The IPC buffer frame capability.
    pub(crate) ipc_frame_cap: ThreadCap,
    /// init-assigned per-process thread id for supervisor-managed
    /// workers. Zero means this descriptor was not created through
    /// `INIT_THREAD_CREATE`.
    pub init_tid: u16,
    /// Non-zero when stack / IPC memory is owned by mmsrv mappings rather
    /// than direct FRAME caps in this CSpace.
    pub mmsrv_backed: u8,

    /// Base address of the thread's stack mapping.
    pub stack_base: u64,
    /// Size of the thread's stack (bytes).
    pub stack_size: u64,
    /// Base address of the TLS region mapping.
    pub tls_region: u64,
    /// Size of the TLS region (bytes).
    pub tls_region_size: u64,
    /// IPC buffer virtual address.
    pub ipc_buf_vaddr: u64,
    /// Pointer to the thread's ThreadLocalBlock within its TLS region.
    pub tls_ptr: *mut ThreadLocalBlock,

    /// Stack frame capabilities (a consecutive slot run). `None` when not
    /// applicable (main thread, personality-managed, or mmsrv-backed worker).
    pub(crate) stack_frames: Option<OwnedSlotRange>,
    /// TLS region frame capabilities (a consecutive slot run).
    pub(crate) tls_frames: Option<OwnedSlotRange>,

    /// Globally unique thread ID (assigned by substrate).
    pub thread_id: u64,

    /// Who owns this thread's resources for cleanup purposes.
    pub owner: ThreadOwner,

    /// Personality extension data (opaque — cast by personality layer).
    pub personality_data: *mut u8,
    /// Personality-specific cleanup (called before substrate resource cleanup).
    pub personality_cleanup: Option<PersonalityCleanupFn>,
    /// Personality-specific fork-child reinit.
    pub personality_fork_child: Option<PersonalityForkChildFn>,
}

// SAFETY: ThreadDesc fields are synchronized through atomic CAS on `state`.
// Raw pointer fields are only accessed by the owning thread or after the
// state CAS establishes a happens-before relationship.
unsafe impl Send for ThreadDesc {}
unsafe impl Sync for ThreadDesc {}

impl ThreadDesc {
    pub const fn zeroed() -> Self {
        ThreadDesc {
            state: AtomicU32::new(TD_UNUSED),
            generation: AtomicU32::new(0),
            tcb_cap: ThreadCap::None,
            sc_cap: ThreadCap::None,
            ipc_frame_cap: ThreadCap::None,
            init_tid: 0,
            mmsrv_backed: 0,
            stack_base: 0,
            stack_size: 0,
            tls_region: 0,
            tls_region_size: 0,
            ipc_buf_vaddr: 0,
            tls_ptr: core::ptr::null_mut(),
            stack_frames: None,
            tls_frames: None,
            thread_id: 0,
            owner: ThreadOwner::Main,
            personality_data: core::ptr::null_mut(),
            personality_cleanup: None,
            personality_fork_child: None,
        }
    }

    /// Release every owned capability this thread holds (delete +
    /// free), leaving the cap fields empty. Borrowed slots (the main thread's
    /// `CAP_SELF_TCB` / role `SchedContext`) are left untouched. Used by the
    /// reaper and the spawn rollback on a worker thread.
    pub(crate) fn release_caps(&mut self) {
        self.tcb_cap = ThreadCap::None;
        self.sc_cap = ThreadCap::None;
        self.ipc_frame_cap = ThreadCap::None;
        self.stack_frames = None;
        self.tls_frames = None;
    }

    /// Give up every owned capability *without* releasing it, leaving the cap
    /// fields empty. Used in the fork child, whose inherited slot indices are
    /// stale COW copies that must not be deleted — a later reuse of this
    /// descriptor would otherwise revoke caps belonging to the child's fresh
    /// CSpace.
    pub(crate) fn forget_caps(&mut self) {
        self.tcb_cap.forget();
        self.sc_cap.forget();
        self.ipc_frame_cap.forget();
        core::mem::forget(self.stack_frames.take());
        core::mem::forget(self.tls_frames.take());
    }
}

// ---------------------------------------------------------------------------
// Thread pool
// ---------------------------------------------------------------------------

static mut THREAD_POOL: [ThreadDesc; MAX_THREADS] = [const { ThreadDesc::zeroed() }; MAX_THREADS];

static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);

/// Get a raw pointer to thread pool slot `index`.
#[inline]
pub fn thread_desc(index: usize) -> *mut ThreadDesc {
    unsafe {
        let base = &raw mut THREAD_POOL as *mut ThreadDesc;
        base.add(index)
    }
}

/// Allocate an unused thread pool slot. Returns the slot index, or None if full.
pub fn alloc_thread_desc() -> Option<usize> {
    unsafe {
        for i in 0..MAX_THREADS {
            let desc = thread_desc(i);
            if (*desc)
                .state
                .compare_exchange(TD_UNUSED, TD_RUNNING, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                (*desc).generation.fetch_add(1, Ordering::Relaxed);
                return Some(i);
            }
        }
    }
    None
}

/// Assign a globally unique thread ID.
pub fn next_thread_id() -> u64 {
    NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed)
}

/// Extract the `ThreadDesc` pointer from a `ThreadLocalBlock`'s opaque `desc` field.
#[inline]
pub unsafe fn desc_from_tls(tls: *mut ThreadLocalBlock) -> *mut ThreadDesc {
    unsafe { (*tls).desc as *mut ThreadDesc }
}

// ---------------------------------------------------------------------------
// TLS guard flag
// ---------------------------------------------------------------------------

/// Set to `true` after at least one thread's TP register has been configured.
/// Guards `read_tp()` — reading FS:[0] when FS_BASE is 0 would fault.
#[unsafe(no_mangle)]
pub static THREAD_LOCAL_ACTIVE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Architecture-specific TP register access
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn trona_runtime_read_tp_raw() -> u64;
}

/// Read the thread pointer register value.
///
/// x86_64: reads `%fs:[0]` (self-pointer in ThreadLocalBlock).
/// aarch64: reads `TPIDR_EL0`.
///
/// # Safety
/// `THREAD_LOCAL_ACTIVE` must be true (TP has been set for this thread).
#[inline]
pub unsafe fn read_tp() -> u64 {
    // SAFETY: Caller guarantees TP is active for this thread.
    unsafe { trona_runtime_read_tp_raw() }
}

/// Derive the `ThreadLocalBlock` pointer from the architecture TP value.
///
/// x86_64 Variant II: TP == &ThreadLocalBlock (self_ptr).
/// aarch64: TP → AbiThreadPointerBlock → runtime_tcb → ThreadLocalBlock.
#[inline]
pub unsafe fn runtime_tcb_from_tp(tp: u64) -> *mut ThreadLocalBlock {
    #[cfg(target_arch = "x86_64")]
    {
        tp as *mut ThreadLocalBlock
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if tp == 0 {
            core::ptr::null_mut()
        } else {
            (*(tp as *const AbiThreadPointerBlock)).runtime_tcb
        }
    }
}

/// Set the aarch64 ABI header's `runtime_tcb` pointer.
/// No-op on x86_64 (TP is the TCB itself).
pub unsafe fn install_runtime_tcb_anchor(tp: u64, tcb: *mut ThreadLocalBlock) {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = tp;
        let _ = tcb;
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let abi = tp as *mut AbiThreadPointerBlock;
        (*abi).runtime_tcb = tcb;
        (*abi).reserved = 0;
    }
}

// ---------------------------------------------------------------------------
// current_tls / current_ipc_ctx — the core TLS accessors
// ---------------------------------------------------------------------------

/// Return the current thread's TLS block, or `None` if TLS is not active.
///
/// This is the substrate-level accessor. All threads with TLS (main, worker,
/// POSIX, Win32) return `Some`. Personality-specific code checks `desc.owner`
/// internally for personality-gated operations.
#[inline]
pub fn current_tls() -> Option<*mut ThreadLocalBlock> {
    if !THREAD_LOCAL_ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let tp = unsafe { read_tp() };
    if tp == 0 {
        return None;
    }
    let tls = unsafe { runtime_tcb_from_tp(tp) };
    if tls.is_null() { None } else { Some(tls) }
}

/// Return the current thread's IPC context.
///
/// If TLS is active, returns the per-thread IPC context from the TLS block.
/// Otherwise falls back to the global `__trona_ipc_ctx`.
#[inline]
pub fn current_ipc_ctx() -> *mut IpcContext {
    if let Some(tls) = current_tls() {
        unsafe { &raw mut (*tls).ipc_ctx }
    } else {
        &raw mut crate::__trona_ipc_ctx
    }
}

// ---------------------------------------------------------------------------
// Static TLS helpers
// ---------------------------------------------------------------------------

/// Maximum static TLS data size for the main thread's statically-allocated block.
pub const MAX_ELF_TLS_SIZE: usize = 4096;

/// Return the size of the aarch64 ABI thread pointer header (0 on x86_64).
#[inline]
pub const fn abi_tcb_size() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        0
    }
    #[cfg(target_arch = "aarch64")]
    {
        core::mem::size_of::<AbiThreadPointerBlock>() as u64
    }
}

/// Total static TLS footprint (from rtld's `__trona_tls_memsz`).
#[inline]
pub fn static_tls_total_memsz() -> u64 {
    unsafe { *(&raw const crate::__trona_tls_memsz) }
}

/// Static TLS alignment requirement.
#[inline]
pub fn static_tls_align() -> u64 {
    let align = unsafe { *(&raw const crate::__trona_tls_align) };
    if align < 1 { 1 } else { align }
}

#[inline]
fn static_tls_module_count() -> usize {
    let count = unsafe { *(&raw const crate::__trona_tls_module_count) as usize };
    core::cmp::min(count, MAX_STATIC_TLS_MODULES)
}

#[inline]
unsafe fn static_tls_module(index: usize) -> StaticTlsModule {
    unsafe {
        let modules = (&raw const crate::__trona_tls_modules) as *const StaticTlsModule;
        core::ptr::read(modules.add(index))
    }
}

/// Default ELF TLS data base address from a TP value.
#[inline]
fn default_tls_base_from_tp(tp: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        tp.wrapping_sub(static_tls_total_memsz())
    }
    #[cfg(target_arch = "aarch64")]
    {
        tp.wrapping_add(abi_tcb_size())
    }
}

/// Initialize static TLS data (.tdata copy, .tbss zero) for a given TP value.
///
/// # Safety
/// `tp` must point to a valid, writable TLS region with enough space for the
/// static TLS footprint.
pub unsafe fn initialize_static_tls_for_tp(tp: u64) {
    let tls_memsz = static_tls_total_memsz();
    if tls_memsz == 0 || tls_memsz > MAX_ELF_TLS_SIZE as u64 {
        return;
    }

    unsafe {
        let tls_base = default_tls_base_from_tp(tp);
        crate::udebug!(|_lb| {
            _lb.str(b"[TRONA-TLS] init_static: tp=");
            _lb.hex(tp);
            _lb.str(b" tls_base=");
            _lb.hex(tls_base);
            _lb.str(b" memsz=");
            _lb.hex(tls_memsz);
            _lb.str(b"\n");
        });
        core::ptr::write_bytes(tls_base as *mut u8, 0, tls_memsz as usize);

        let module_count = static_tls_module_count();
        if module_count == 0 {
            let tls_filesz = *(&raw const crate::__trona_tls_filesz);
            let tls_template = *(&raw const crate::__trona_tls_template);
            if tls_template != 0 && tls_filesz > 0 {
                crate::udebug!(|_lb| {
                    _lb.str(b"[TRONA-TLS] init_static single-module: template=");
                    _lb.hex(tls_template);
                    _lb.str(b" filesz=");
                    _lb.hex(tls_filesz);
                    _lb.str(b" dst=");
                    _lb.hex(tls_base);
                    _lb.str(b"\n");
                });
                core::ptr::copy_nonoverlapping(
                    tls_template as *const u8,
                    tls_base as *mut u8,
                    tls_filesz as usize,
                );
            }
            return;
        }

        for i in 0..module_count {
            let module = static_tls_module(i);
            if module.module_id == 0 || module.memsz == 0 {
                continue;
            }
            if module.template_addr != 0 && module.filesz > 0 {
                let dst = tp.wrapping_add(module.tp_offset as u64) as *mut u8;
                crate::udebug!(|_lb| {
                    _lb.str(b"[TRONA-TLS] init_static module=");
                    _lb.hex(module.module_id);
                    _lb.str(b" template=");
                    _lb.hex(module.template_addr);
                    _lb.str(b" filesz=");
                    _lb.hex(module.filesz);
                    _lb.str(b" dst=");
                    _lb.hex(dst as u64);
                    _lb.str(b"\n");
                });
                core::ptr::copy_nonoverlapping(
                    module.template_addr as *const u8,
                    dst,
                    module.filesz as usize,
                );
            }
        }
    }
}

/// Resolve a TLS variable address from TP, module ID, and offset.
pub unsafe fn tls_addr_from_tp(tp: u64, module_id: u64, offset: u64) -> *mut u8 {
    let module_count = static_tls_module_count();
    if module_id != 0 && module_count != 0 {
        unsafe {
            for i in 0..module_count {
                let module = static_tls_module(i);
                if module.module_id == module_id {
                    return tp
                        .wrapping_add(module.tp_offset as u64)
                        .wrapping_add(offset) as *mut u8;
                }
            }
        }
    }
    default_tls_base_from_tp(tp).wrapping_add(offset) as *mut u8
}

/// Resolve a TLS variable address for the current thread.
pub unsafe fn tls_addr(module_id: u64, offset: u64) -> *mut u8 {
    unsafe { tls_addr_from_tp(read_tp(), module_id, offset) }
}

// ---------------------------------------------------------------------------
// TLS region sizing for spawned threads
// ---------------------------------------------------------------------------

#[inline]
fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.saturating_add(align - 1) & !(align - 1)
    }
}

/// Compute the TLS region size needed per spawned thread.
///
/// Matches the layout calculation in pthread.rs:383-422 so that the region
/// is large enough for `initialize_static_tls_for_tp` + `install_runtime_tcb_anchor`.
pub fn thread_tls_region_size() -> u64 {
    let tls_memsz = static_tls_total_memsz();
    let tls_align = static_tls_align().max(16);
    let tcb_size = core::mem::size_of::<ThreadLocalBlock>() as u64;
    let runtime_tcb_align = core::mem::align_of::<ThreadLocalBlock>() as u64;

    #[cfg(target_arch = "x86_64")]
    {
        // Variant II: [ELF TLS | ThreadLocalBlock]
        let max_align = tls_align.max(runtime_tcb_align);
        align_up(tls_memsz + tcb_size + (max_align - 1), 4096)
    }
    #[cfg(target_arch = "aarch64")]
    {
        // [ABI header | ELF TLS | ThreadLocalBlock]
        let abi_size = abi_tcb_size();
        align_up(
            abi_size + tls_memsz + (runtime_tcb_align - 1) + tcb_size + tls_align,
            4096,
        )
    }
}

// ---------------------------------------------------------------------------
// Main thread TLS block (static allocation)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[repr(C, align(64))]
struct MainTlsBlock {
    elf_tls: [u8; MAX_ELF_TLS_SIZE],
    tcb: ThreadLocalBlock,
}

#[cfg(target_arch = "aarch64")]
#[repr(C, align(64))]
struct MainTlsBlock {
    abi_tcb: AbiThreadPointerBlock,
    elf_tls: [u8; MAX_ELF_TLS_SIZE],
    tcb: ThreadLocalBlock,
}

#[cfg(target_arch = "x86_64")]
static mut MAIN_TLS_BLOCK: MainTlsBlock = MainTlsBlock {
    elf_tls: [0u8; MAX_ELF_TLS_SIZE],
    tcb: ThreadLocalBlock::zeroed(),
};

#[cfg(target_arch = "aarch64")]
static mut MAIN_TLS_BLOCK: MainTlsBlock = MainTlsBlock {
    abi_tcb: AbiThreadPointerBlock::zeroed(),
    elf_tls: [0u8; MAX_ELF_TLS_SIZE],
    tcb: ThreadLocalBlock::zeroed(),
};

// ---------------------------------------------------------------------------
// Main thread initialization
// ---------------------------------------------------------------------------

/// Initialize TLS for the main thread.
///
/// Called during process startup (from CRT or `_start`). Sets up the ELF
/// TLS data area, configures the hardware thread pointer, and allocates
/// thread pool slot 0 for the main thread descriptor.
///
/// # Safety
/// Must be called exactly once during process initialization, before
/// any other threads are created.
pub unsafe fn init_main_thread_tls() {
    unsafe {
        let tls = &raw mut MAIN_TLS_BLOCK.tcb;
        #[cfg(target_arch = "x86_64")]
        let tp = tls as u64;
        #[cfg(target_arch = "aarch64")]
        let tp = (&raw mut MAIN_TLS_BLOCK.abi_tcb) as u64;

        crate::udebug!(|_lb| {
            _lb.str(b"[TRONA-TLS] init_main: block=");
            _lb.hex(&raw mut MAIN_TLS_BLOCK as u64);
            _lb.str(b" tcb=");
            _lb.hex(tls as u64);
            _lb.str(b" tp=");
            _lb.hex(tp);
            _lb.str(b"\n");
        });

        initialize_static_tls_for_tp(tp);
        install_runtime_tcb_anchor(tp, tls);

        // Self-pointer (x86_64 TLS ABI)
        (*tls).self_ptr = tls;

        // Copy global IPC context into TLS
        (*tls).ipc_ctx.ipc_buffer = crate::__trona_ipc_ctx.ipc_buffer;
        (*tls).ipc_ctx.send_cap_count = crate::__trona_ipc_ctx.send_cap_count;

        // Main thread is thread 0
        (*tls).thread_id = 0;

        // Initialize main thread descriptor (slot 0)
        let desc = thread_desc(0);
        (*desc).state.store(TD_RUNNING, Ordering::Release);
        (*desc).tcb_cap = ThreadCap::borrowed(CAP_SELF_TCB);
        (*desc).sc_cap = ThreadCap::borrowed(CapRef::flat(*(&raw const crate::__trona_sc_cap)));
        (*desc).owner = ThreadOwner::Main;
        (*desc).thread_id = 0;
        (*desc).tls_ptr = tls;
        (*tls).desc = desc as *mut u8;

        // Set the architecture thread pointer via kernel invoke
        let err = invoke::tcb_set_tls_base(CAP_SELF_TCB, tp);

        // Only mark TLS as initialized if the kernel accepted the base address
        if err == 0 {
            THREAD_LOCAL_ACTIVE.store(true, Ordering::Release);
        }
    }
}

// ---------------------------------------------------------------------------
// Thread cleanup
// ---------------------------------------------------------------------------

/// Clean up a non-running thread. Must be called by an external thread
/// (the reaper), never by the thread itself.
///
/// 1. Personality cleanup (join notify, extension data free, etc.)
/// 2. Resource cleanup based on owner:
///    - Worker: substrate unmaps stack/IPC/TLS, deletes caps
///    - Personality: personality already handled resource cleanup
///    - Main: no-op (lives for process lifetime)
/// 3. Return pool slot (state → TD_UNUSED)
pub unsafe fn cleanup_thread(desc: *mut ThreadDesc) {
    unsafe {
        // 1. Personality cleanup
        if let Some(f) = (*desc).personality_cleanup {
            f(desc);
        }

        // 2. Resource cleanup by owner
        match (*desc).owner {
            ThreadOwner::Worker => {
                if (*desc).mmsrv_backed != 0 {
                    if (*desc).stack_base != 0 && (*desc).stack_size != 0 {
                        let _ = crate::client::mm::munmap(
                            (*desc).stack_base as *mut u8,
                            (*desc).stack_size,
                        );
                    }
                    if (*desc).ipc_buf_vaddr != 0 {
                        let _ = crate::client::mm::munmap((*desc).ipc_buf_vaddr as *mut u8, 4096);
                    }
                } else {
                    // Unmap stack
                    if (*desc).stack_base != 0 && (*desc).stack_size != 0 {
                        let pages = (*desc).stack_size / 4096;
                        for p in 0..pages {
                            invoke::vspace_unmap(CAP_SELF_VSPACE, (*desc).stack_base + p * 4096);
                        }
                    }
                    // Unmap IPC buffer
                    if (*desc).ipc_buf_vaddr != 0 {
                        invoke::vspace_unmap(CAP_SELF_VSPACE, (*desc).ipc_buf_vaddr);
                    }
                    // Unmap TLS region
                    if (*desc).tls_region != 0 && (*desc).tls_region_size != 0 {
                        let pages = (*desc).tls_region_size / 4096;
                        for p in 0..pages {
                            invoke::vspace_unmap(CAP_SELF_VSPACE, (*desc).tls_region + p * 4096);
                        }
                    }
                }
                // Tear down the thread's owned kernel-object caps. Dropping
                // each owned slot returns it to the allocator only once its
                // CNode entry is known empty; derived caps are preserved by
                // CNode_Delete's CDT re-rooting path. The frame runs free
                // their whole range.
                (*desc).release_caps();
            }
            ThreadOwner::Personality => {
                // Personality cleanup already handled everything
            }
            ThreadOwner::Main => {
                // Main thread is never cleaned up
            }
        }

        // 3. Clear and return slot
        (*desc).personality_data = core::ptr::null_mut();
        (*desc).personality_cleanup = None;
        (*desc).personality_fork_child = None;
        (*desc).tls_ptr = core::ptr::null_mut();
        (*desc).init_tid = 0;
        (*desc).mmsrv_backed = 0;
        // Clear the VA fields too so a reused descriptor never carries stale
        // mappings into a later spawn's early-failure rollback (the untyped
        // `spawn_fn` only sets them after the frame retypes succeed).
        (*desc).stack_base = 0;
        (*desc).stack_size = 0;
        (*desc).tls_region = 0;
        (*desc).tls_region_size = 0;
        (*desc).ipc_buf_vaddr = 0;
        (*desc).state.store(TD_UNUSED, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// post_fork_child — called from fork.S child entry
// ---------------------------------------------------------------------------

/// Reinitialize thread pool and main thread descriptor after fork.
///
/// Called by `fork_child_entry` (assembly) before register restore.
/// The child has a COW copy of the parent's address space. Main thread
/// descriptor caps are stale (parent's values). Non-main slots must be
/// invalidated (child is single-threaded).
///
/// # Safety
/// Must be called exactly once in the fork child, before the child
/// returns to user code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _trona_post_fork_child() {
    unsafe {
        // 1. Main thread descriptor: update caps for child
        let desc = thread_desc(0);
        (*desc).tcb_cap = ThreadCap::borrowed(CAP_SELF_TCB);

        // 2. Clean up non-main slots: unmap VA regions and invalidate.
        //
        // Fork child has a COW copy of parent's CSpace. We must NOT run the
        // normal personality cleanup path here because it is allowed to
        // delete caps or perform full stack teardown. Instead, reclaim only
        // child-local VA mappings and invalidate the descriptor slots; the
        // main-thread personality hook below rebuilds personality state.
        for i in 1..MAX_THREADS {
            let d = thread_desc(i);
            let st = (*d).state.load(Ordering::Acquire);
            if st == TD_UNUSED {
                continue;
            }

            // Unmap stack pages (VA only, not cap delete)
            if (*d).stack_base != 0 && (*d).stack_size != 0 {
                let pages = (*d).stack_size / 4096;
                for p in 0..pages {
                    invoke::vspace_unmap(CAP_SELF_VSPACE, (*d).stack_base + p * 4096);
                }
            }
            // Unmap IPC buffer
            if (*d).ipc_buf_vaddr != 0 {
                invoke::vspace_unmap(CAP_SELF_VSPACE, (*d).ipc_buf_vaddr);
            }
            // Unmap TLS region
            if (*d).tls_region != 0 && (*d).tls_region_size != 0 {
                let pages = (*d).tls_region_size / 4096;
                for p in 0..pages {
                    invoke::vspace_unmap(CAP_SELF_VSPACE, (*d).tls_region + p * 4096);
                }
            }

            // Invalidate slot (ABA generation bump). The inherited cap slots
            // are stale COW indices in the child's fresh CSpace — forget them
            // without deleting, or a later reuse of this descriptor would
            // revoke caps that no longer belong to us.
            (*d).forget_caps();
            (*d).state.store(TD_UNUSED, Ordering::Release);
            (*d).generation.fetch_add(1, Ordering::Release);
            (*d).personality_data = core::ptr::null_mut();
            (*d).personality_cleanup = None;
            (*d).personality_fork_child = None;
            (*d).stack_base = 0;
            (*d).stack_size = 0;
            (*d).tls_region = 0;
            (*d).tls_region_size = 0;
            (*d).ipc_buf_vaddr = 0;
            (*d).tls_ptr = core::ptr::null_mut();
        }

        // 3. Reset the substrate slot allocator. The child runs in a brand-new
        // CSpace whose segment layout is described by its own startup CSpace
        // descriptor — the parent's segment table and self-expansion state
        // (cspace_expand_count, runtime_authority_ep, runtime_owner_id,
        // expand_temp_slot, expand_handler) do not apply. After the reset
        // we walk the child's layout to re-register the initial segment(s).
        // Self-expansion stays disabled until the child re-installs an
        // authority EP through the usual `enable_self_expand` /
        // `reserve_expand_temp_slot` path.
        crate::core::slot_alloc::slot_alloc_reset_for_fork();
        let _ = crate::runtime_init_slot_allocator();

        // 3a. Clear parent-owned lazy weak symbols before reinstalling
        // the child's cap table. Missing optional roles stay zero and
        // can be resolved lazily; roles that init delivered explicitly
        // are immediately overwritten with the child's real slots.
        crate::client::lazy_resolve::reset_lazy_caps_for_fork();

        // 3b. Reinstall cap-table roles from the saved runtime descriptor's
        // cap_table_ptr — the same source `runtime_install` uses at startup.
        // init stages the child's fresh cap-table at that VA before entering
        // this trampoline. The inherited auxv is deliberately not used here: it
        // is the parent's and resolves the parent's startup block, whose
        // cap_table_ptr no longer names the child's cap-table, which would
        // leave non-lazy roles (notably ROLE_INIT_CONTROL) zero.
        let _ = crate::spawn::cap_table::runtime_reinstall_from_saved_runtime();
        (*desc).sc_cap = ThreadCap::borrowed(CapRef::flat(core::ptr::read_volatile(
            &raw const crate::__trona_sc_cap,
        )));

        if !(*desc).tls_ptr.is_null() {
            let tls = (*desc).tls_ptr;
            (*tls).ipc_ctx.send_cap_count = 0;
            ipc::clear_send_caps_ctx(&raw mut (*tls).ipc_ctx);
            ipc::clear_mp_metadata_ctx(&raw mut (*tls).ipc_ctx);
        } else {
            crate::__trona_ipc_ctx.send_cap_count = 0;
            ipc::clear_send_caps_ctx(&raw mut crate::__trona_ipc_ctx);
            ipc::clear_mp_metadata_ctx(&raw mut crate::__trona_ipc_ctx);
        }

        // 4. Personality-specific fork reinit for main thread
        if let Some(f) = (*desc).personality_fork_child {
            f(desc);
        }

        // 5. Reset thread ID counter (child is a new process)
        NEXT_THREAD_ID.store(1, Ordering::Release);
    }
}
