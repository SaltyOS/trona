//! Thread-Local Storage (TLS) accessors for the POSIX personality.
//!
//! The canonical TLS infrastructure (ThreadLocalBlock, MainTlsBlock, TLS
//! initialization, TP register management, thread pool) now lives in the
//! substrate crate (`trona::tls`). This module re-exports substrate types
//! for backward compatibility and provides POSIX-specific helpers:
//!
//! - `current_errno()` — per-thread errno with global fallback
//! - `tls_addr()` — TLS variable address resolution (General Dynamic model)
//!
//! SPDX-License-Identifier: GPL-2.0-only

// Re-export types from uapi for backward compat
pub use trona::types::core::{
    ThreadLocalBlock, CleanupHandler,
    StaticTlsModule, MAX_STATIC_TLS_MODULES,
};

// Re-export substrate TLS constants and functions used by sibling modules
pub use trona::tls::{
    MAX_ELF_TLS_SIZE,
    abi_tcb_size,
    static_tls_total_memsz,
    static_tls_align,
    initialize_static_tls_for_tp,
    install_runtime_tcb_anchor,
};

/// Delegate to the substrate's `current_tls()`.
///
/// Returns the current thread's TLS block pointer, or `None` if TLS
/// has not been initialized for this process.
#[inline]
pub fn current_tls() -> Option<*mut ThreadLocalBlock> {
    trona::tls::current_tls()
}

/// Delegate to the substrate's `current_ipc_ctx()`.
///
/// Returns the per-thread IPC context if TLS is active, otherwise
/// falls back to the global `__trona_ipc_ctx`.
#[inline]
pub fn current_ipc_ctx() -> *mut trona::types::core::IpcContext {
    trona::tls::current_ipc_ctx()
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
/// Delegates to `trona::tls::tls_addr()`.
pub unsafe fn tls_addr(module_id: u64, offset: u64) -> *mut u8 {
    unsafe { trona::tls::tls_addr(module_id, offset) }
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
        trona::tls::init_main_thread_tls();

        // After substrate TLS init, initialize the POSIX personality
        // for the main thread's descriptor.
        if let Some(tls) = current_tls() {
            crate::pthread::init_main_thread_control(tls);
        }
    }
}
