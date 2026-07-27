//! Thread-Local Storage (TLS) accessors for the POSIX personality.
//!
//! The canonical TLS infrastructure (ThreadLocalBlock, MainTlsBlock, TLS
//! initialization, TP register management, thread pool) now lives in the
//! substrate crate (`trona_runtime::thread::tls`). This module re-exports substrate types
//! for backward compatibility and provides POSIX-specific helpers:
//!
//! - `current_errno()` — per-thread errno with global fallback
//! - `tls_addr()` — TLS variable address resolution (General Dynamic model)
//!
//! SPDX-License-Identifier: GPL-2.0-only

// Re-export the TLS-block types from substrate so callers in this
// crate's other modules and basaltc can use them through `trona_posix::tls::*`
// without reaching into substrate directly.
pub use trona_kernel::core_types::{
    CleanupHandler, MAX_STATIC_TLS_MODULES, StaticTlsModule, ThreadLocalBlock,
};

// Re-export substrate TLS constants and functions used by sibling modules
pub use trona_runtime::thread::tls::{
    MAX_ELF_TLS_SIZE, abi_tcb_size, initialize_static_tls_for_tp, install_runtime_tcb_anchor,
    static_tls_align, static_tls_total_memsz,
};

/// Delegate to the substrate's `current_tls()`.
///
/// Returns the current thread's TLS block pointer, or `None` if TLS
/// has not been initialized for this process.
#[inline]
pub fn current_tls() -> Option<*mut ThreadLocalBlock> {
    trona_runtime::thread::tls::current_tls()
}

/// Delegate to the substrate's `current_ipc_ctx()`.
///
/// Returns the per-thread IPC context if TLS is active, otherwise
/// falls back to the global `__trona_ipc_ctx`.
#[inline]
pub fn current_ipc_ctx() -> *mut trona_kernel::core_types::IpcContext {
    trona_runtime::thread::tls::current_ipc_ctx()
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

/// Resolve a TLS variable address for the current thread.
///
/// Delegates to `trona_runtime::thread::tls::tls_addr()`.
pub unsafe fn tls_addr(module_id: u64, offset: u64) -> *mut u8 {
    unsafe { trona_runtime::thread::tls::tls_addr(module_id, offset) }
}

/// Initialize TLS for the main thread — POSIX personality wrapper.
///
/// Calls the substrate's `init_main_thread_tls()` which handles all
/// hardware TP setup, static TLS initialization, and thread descriptor
/// allocation. POSIX-specific personality registration (fork callback,
/// cleanup function) is done by `init_main_thread_control()` in pthread.rs,
/// which the substrate calls back into via the `desc` pointer.
///
/// # Safety
/// Must be called exactly once during process initialization, before
/// any other threads are created.
pub unsafe fn init_main_thread_tls() {
    unsafe {
        trona_runtime::thread::tls::init_main_thread_tls();

        // Install the POSIX cancellation hook into the substrate sync layer
        // so that blocking primitives (Condvar::wait, etc.) can invoke
        // pthread_testcancel() when a cancellation is pending.
        trona_runtime::thread::sync::install_cancel_hook(posix_cancel_impl);

        // After substrate TLS init, initialize the POSIX personality
        // for the main thread's descriptor.
        if let Some(tls) = current_tls() {
            crate::pthread::init_main_thread_control(tls);
        }
    }
}

/// Cancellation hook installed into the substrate sync layer.
///
/// Called by blocking primitives after they observe `cancel_pending` on
/// the current thread's TLS block.
///
/// # Safety
///
/// This function calls `pthread_testcancel()`, which may unwind the thread
/// via `pthread_exit`. The caller (substrate sync code) must not hold any
/// locks when invoking this hook.
unsafe fn posix_cancel_impl() {
    unsafe { crate::pthread::pthread_testcancel() };
}
