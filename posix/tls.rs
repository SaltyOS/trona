//! Thread-Local Storage (TLS) block layout and accessors
//!
//! The runtime keeps a `ThreadLocalBlock` per thread, but the hardware thread
//! pointer layout is architecture-specific:
//!
//! - x86_64 uses Variant II: TP points directly at the runtime TCB.
//! - aarch64 uses an ABI header at TP and places ELF TLS at positive offsets.
//!
//! ## ELF TLS (Variant II) Layout
//!
//! x86_64 uses Variant II TLS, where ELF TLS data (`.tdata`/`.tbss`) is placed
//! *below* the thread pointer (TP). The `MainTlsBlock` struct encodes this:
//!
//! ```text
//! [elf_tls: MAX_ELF_TLS_SIZE bytes] [tcb: ThreadLocalBlock]
//!                                    ^-- TP (fs:0 = self-pointer)
//! ```
//!
//! TLS variables are accessed at `TP - aligned_memsz + offset`.
//!
//! The main thread's TLS block is statically allocated. Spawned threads have
//! their TLS blocks placed at the top of their stack (below the guard page).
//!
//! Thread lifecycle fields (stack, caps, join state) live in the ThreadControl
//! pool (`pthread.rs`), not here. TLS holds only per-thread runtime state.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::IpcContext;
use ::core::sync::atomic::{AtomicBool, Ordering};

/// Set to `true` after `init_main_thread_tls()` has configured the hardware
/// thread pointer. Prevents `current_tls()` from reading an unmapped TP.
static TLS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Maximum static TLS data size across the executable and loaded DSOs.
///
/// This must be large enough for the combined PT_TLS footprint that rtld
/// exports for the process. 4096 bytes covers the current C++ runtime set.
pub const MAX_ELF_TLS_SIZE: usize = 4096;

// Re-export from substrate (canonical definitions live in trona::types)
pub use trona::types::core::{StaticTlsModule, MAX_STATIC_TLS_MODULES};

#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct AbiThreadPointerBlock {
    runtime_tcb: *mut ThreadLocalBlock,
    reserved: u64,
}

#[cfg(target_arch = "aarch64")]
impl AbiThreadPointerBlock {
    const fn zeroed() -> Self {
        AbiThreadPointerBlock {
            runtime_tcb: ::core::ptr::null_mut(),
            reserved: 0,
        }
    }
}

/// Per-thread local storage block.
///
/// Layout is `#[repr(C)]` for ABI stability. The `self_ptr` field MUST be
/// first — the x86_64 TLS ABI mandates that `%fs:0` dereferences to the
/// TLS block's own address.
///
/// Lifecycle fields (stack base/size, cap slots, join state, exit value)
/// have been moved to `ThreadControl` in `pthread.rs`. The `control`
/// back-pointer connects this TLS block to its owning ThreadControl slot.
#[repr(C)]
pub struct ThreadLocalBlock {
    /// Self-pointer: `%fs:0 == &self` (x86_64 TLS ABI requirement)
    pub self_ptr: *mut ThreadLocalBlock,
    /// Per-thread IPC context (IPC buffer pointer + send-cap count)
    pub ipc_ctx: IpcContext,
    /// Thread ID (unique per thread within a process)
    pub thread_id: u64,
    /// Per-thread errno value
    pub errno: i32,
    /// Padding for alignment
    _pad0: i32,
    /// Back-pointer to owning ThreadControl slot (opaque to avoid circular deps)
    pub control: *mut u8,
    /// Cancellation state: 0=ENABLE, 1=DISABLE
    pub cancel_state: u32,
    /// Cancellation type: 0=DEFERRED (only type supported)
    pub cancel_type: u32,
    /// Set to 1 when cancellation has been requested
    pub cancel_pending: u32,
    _pad1: u32,
    /// LIFO stack of cleanup handlers (intrusive linked list)
    pub cleanup_stack: *mut CleanupHandler,
    /// Futex address the thread is currently blocked on (for cancel wake).
    /// Set before futex_wait at cancellation points, cleared after return.
    /// 0 means the thread is not blocked on any cancellation-point futex.
    pub blocked_futex_addr: ::core::sync::atomic::AtomicU64,

    // ----- basaltc per-thread state (appended to preserve existing offsets) -----

    /// Per-thread strtok() save pointer (used by basaltc strtok).
    pub strtok_save: *mut u8,
    /// Per-thread `struct tm` buffer for gmtime()/localtime() (56 bytes).
    pub libc_tm_buf: [u8; 56],
    /// Per-thread asctime() buffer (64 bytes).
    pub libc_asctime_buf: [u8; 64],
    /// Per-thread ctime() buffer (64 bytes).
    pub libc_ctime_buf: [u8; 64],
}

/// Cleanup handler node for pthread_cleanup_push/pop.
#[repr(C)]
pub struct CleanupHandler {
    pub routine: unsafe extern "C" fn(*mut u8),
    pub arg: *mut u8,
    pub next: *mut CleanupHandler,
}

unsafe impl Send for ThreadLocalBlock {}
unsafe impl Sync for ThreadLocalBlock {}
unsafe impl Send for CleanupHandler {}
unsafe impl Sync for CleanupHandler {}

impl ThreadLocalBlock {
    /// Create a zeroed TLS block with self_ptr set to null.
    /// The caller must set `self_ptr = &mut self as *mut _` after placement.
    pub const fn zeroed() -> Self {
        ThreadLocalBlock {
            self_ptr: ::core::ptr::null_mut(),
            ipc_ctx: IpcContext::new(),
            thread_id: 0,
            errno: 0,
            _pad0: 0,
            control: ::core::ptr::null_mut(),
            cancel_state: 0,
            cancel_type: 0,
            cancel_pending: 0,
            _pad1: 0,
            cleanup_stack: ::core::ptr::null_mut(),
            blocked_futex_addr: ::core::sync::atomic::AtomicU64::new(0),
            strtok_save: ::core::ptr::null_mut(),
            libc_tm_buf: [0; 56],
            libc_asctime_buf: [0; 64],
            libc_ctime_buf: [0; 64],
        }
    }
}

/// Combined static TLS storage for the main thread.
///
/// x86_64 uses Variant II (`[elf_tls][tcb]`, TP = `tcb`), while aarch64 uses
/// an ABI header followed by ELF TLS (`[abi_tcb][elf_tls][tcb]`, TP = `abi_tcb`).
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

/// Static TLS block for the main thread.
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

#[inline]
pub const fn abi_tcb_size() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        0
    }
    #[cfg(target_arch = "aarch64")]
    {
        ::core::mem::size_of::<AbiThreadPointerBlock>() as u64
    }
}

#[inline]
pub fn static_tls_total_memsz() -> u64 {
    unsafe { *(&raw const trona::__trona_tls_memsz) }
}

#[inline]
pub fn static_tls_align() -> u64 {
    let align = unsafe { *(&raw const trona::__trona_tls_align) };
    if align < 1 { 1 } else { align }
}

#[inline]
fn static_tls_module_count() -> usize {
    let count = unsafe { *(&raw const trona::__trona_tls_module_count) as usize };
    ::core::cmp::min(count, MAX_STATIC_TLS_MODULES)
}

#[inline]
unsafe fn static_tls_module(index: usize) -> StaticTlsModule {
    unsafe {
        let modules = (&raw const trona::__trona_tls_modules) as *const StaticTlsModule;
        ::core::ptr::read(modules.add(index))
    }
}

#[inline]
unsafe fn current_tp_value() -> u64 {
    let ptr: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        ::core::arch::asm!(
            "mov {}, fs:[0]",
            out(reg) ptr,
            options(nostack, pure, readonly)
        );
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // TPIDR_EL0 holds the thread pointer on aarch64
        ::core::arch::asm!(
            "mrs {}, TPIDR_EL0",
            out(reg) ptr,
            options(nostack, pure, readonly)
        );
    }
    ptr
}

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

#[inline]
unsafe fn runtime_tcb_from_tp(tp: u64) -> *mut ThreadLocalBlock {
    #[cfg(target_arch = "x86_64")]
    {
        tp as *mut ThreadLocalBlock
    }
    #[cfg(target_arch = "aarch64")]
    {
        if tp == 0 {
            ::core::ptr::null_mut()
        } else {
            unsafe { (*(tp as *const AbiThreadPointerBlock)).runtime_tcb }
        }
    }
}

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

pub(crate) unsafe fn initialize_static_tls_for_tp(tp: u64) {
    let tls_memsz = static_tls_total_memsz();
    if tls_memsz == 0 || tls_memsz > MAX_ELF_TLS_SIZE as u64 {
        return;
    }

    unsafe {
        let tls_base = default_tls_base_from_tp(tp);
        ::core::ptr::write_bytes(tls_base as *mut u8, 0, tls_memsz as usize);

        let module_count = static_tls_module_count();
        if module_count == 0 {
            let tls_filesz = *(&raw const trona::__trona_tls_filesz);
            let tls_template = *(&raw const trona::__trona_tls_template);
            if tls_template != 0 && tls_filesz > 0 {
                ::core::ptr::copy_nonoverlapping(
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
                ::core::ptr::copy_nonoverlapping(
                    module.template_addr as *const u8,
                    dst,
                    module.filesz as usize,
                );
            }
        }
    }
}

unsafe fn tls_addr_from_tp(tp: u64, module_id: u64, offset: u64) -> *mut u8 {
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

pub unsafe fn tls_addr(module_id: u64, offset: u64) -> *mut u8 {
    unsafe { tls_addr_from_tp(current_tp_value(), module_id, offset) }
}

/// Read the current thread's runtime TLS block pointer from the active TP.
///
/// Returns `None` if TLS has not been initialized for this process
/// (avoids faulting on the unmapped zero page when FS_BASE is 0).
#[inline]
pub fn current_tls() -> Option<*mut ThreadLocalBlock> {
    if !TLS_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }
    let ptr = unsafe { current_tp_value() };
    if ptr == 0 {
        None
    } else {
        let tls = unsafe { runtime_tcb_from_tp(ptr) };
        if tls.is_null() { None } else { Some(tls) }
    }
}

/// Get a pointer to the current thread's IPC context from TLS.
///
/// Falls back to the global `__trona_ipc_ctx` if TLS is not initialized.
#[inline]
pub fn current_ipc_ctx() -> *mut IpcContext {
    if let Some(tls) = current_tls() {
        unsafe { &raw mut (*tls).ipc_ctx }
    } else {
        // Fallback for main thread before TLS is initialized
        &raw mut trona::__trona_ipc_ctx
    }
}

/// Get a pointer to the current thread's errno from TLS.
///
/// Falls back to a global errno if TLS is not initialized.
#[inline]
pub fn current_errno() -> *mut i32 {
    if let Some(tls) = current_tls() {
        unsafe { &raw mut (*tls).errno }
    } else {
        // Fallback: global errno for single-threaded / pre-TLS code
        &raw mut GLOBAL_ERRNO
    }
}

/// Global fallback errno (used before TLS is initialized)
static mut GLOBAL_ERRNO: i32 = 0;

/// Initialize TLS for the main thread.
///
/// Called during process startup (from CRT or `_start`). Sets up the ELF
/// TLS data area (if present) by copying `.tdata` and zeroing `.tbss`,
/// then configures the hardware thread pointer for the architecture ABI.
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

        initialize_static_tls_for_tp(tp);
        install_runtime_tcb_anchor(tp, tls);

        // Set self-pointer (x86_64 TLS ABI)
        (*tls).self_ptr = tls;

        // Copy global IPC context into TLS
        (*tls).ipc_ctx.ipc_buffer = trona::__trona_ipc_ctx.ipc_buffer;
        (*tls).ipc_ctx.send_cap_count = trona::__trona_ipc_ctx.send_cap_count;

        // Main thread is thread 0
        (*tls).thread_id = 0;

        // Set the architecture thread pointer via kernel invoke.
        let err = trona::invoke::tcb_set_tls_base(0, tp); // CAP_SELF_TCB = 0

        // Only mark TLS as initialized if the kernel accepted the base address.
        // If err != 0, TLS stays uninitialized — fallback to globals still works.
        if err == 0 {
            TLS_INITIALIZED.store(true, Ordering::Release);
        }

        // Initialize the main thread's ThreadControl pool slot (slot 0)
        crate::pthread::init_main_thread_control(tls);
    }
}
