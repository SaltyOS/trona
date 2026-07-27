//! SPDX-License-Identifier: GPL-2.0-only
//! RTLD global state management
//!
//! The state is held in a module-private `STATE` static. All access goes
//! through the [`get_state`] / [`get_state_ref`] accessors. The dlfcn entry
//! points reach the state internally and never expose `STATE` to consumers
//! outside this crate. Runtime dlfcn dispatch happens exclusively through
//! the `RtldDlfcnV1` function table published via
//! `trona_loader_runtime_install`.

use crate::common::link_map::RtldState;

/// The single global RTLD state instance.
///
/// Module-private: dlfcn callbacks defined in this crate reach in directly,
/// nothing else does.
static mut STATE: RtldState = RtldState::zeroed();

/// Returns a mutable reference to the global RTLD state.
///
/// # Safety
/// Mutating access must be serialised by `STATE.dl_lock` once concurrent
/// dlopen / dlclose calls are reachable. The startup linker is allowed to
/// mutate freely because it runs single-threaded.
pub unsafe fn get_state() -> &'static mut RtldState {
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

/// Returns a shared reference to the global RTLD state.
///
/// # Safety
/// The caller must ensure no concurrent mutation.
pub unsafe fn get_state_ref() -> &'static RtldState {
    unsafe { &*core::ptr::addr_of!(STATE) }
}

/// `__trona_next_free_slot` — next free slot after RTLD reservations (frame
/// caps + the embedded slot-allocator window). libtrona reads this as the
/// floor for its own slot allocator.
#[unsafe(no_mangle)]
pub static mut __trona_next_free_slot: u32 = 0;

/// `__trona_sc_cap` — scheduling context cap slot.
#[unsafe(no_mangle)]
pub static mut __trona_sc_cap: u32 = 0;

/// `__trona_tls_size` — total static TLS block size.
#[unsafe(no_mangle)]
pub static mut __trona_tls_size: usize = 0;

/// `__trona_tls_align` — maximum TLS alignment.
#[unsafe(no_mangle)]
pub static mut __trona_tls_align: usize = 0;

/// `__trona_tls_offset` — TLS offset from TP.
#[unsafe(no_mangle)]
pub static mut __trona_tls_offset: usize = 0;

/// `__trona_tls_image` — TLS initialisation image address.
#[unsafe(no_mangle)]
pub static mut __trona_tls_image: usize = 0;

/// `__trona_tls_filesz` — TLS initialisation image size.
#[unsafe(no_mangle)]
pub static mut __trona_tls_filesz: usize = 0;

/// Initialises the exported `__trona_*` symbols from the RTLD state.
///
/// # Safety
/// Must be called after RTLD startup is complete and STATE is populated.
pub unsafe fn publish_exports() {
    unsafe {
        let st = &*core::ptr::addr_of!(STATE);
        __trona_next_free_slot = st.next_free_slot;
        __trona_sc_cap = st.sc_cap;
        __trona_tls_size = st.tls_layout.size;
        __trona_tls_align = st.tls_layout.align;
    }
}
