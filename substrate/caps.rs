//! Safe getters for well-known capability slots passed via `AT_TRONA_*` auxv.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Each well-known capability lives in the child cspace at a slot chosen by
//! the spawner. rtld walks the auxv vector at process startup and writes the
//! slot number into the matching `__trona_cap_*` weak symbol on `lib.rs`.
//! Lib code calls the corresponding getter here instead of hard-coding the
//! slot number, so the same code runs against any spawner layout.
//!
//! All getters return `0` when the spawner did not provide that capability;
//! callers must treat `0` as "absent" and either fall back or fail loudly.

use crate::types::Cap;

#[inline]
fn read(p: *const u64) -> u64 {
    // SAFETY: each `__trona_cap_*` weak symbol is initialized exactly once
    // by rtld (or the static CRT) before user code runs. After that point
    // the slot is read-only for the lifetime of the process, so a volatile
    // load through a raw pointer is sound and avoids the Rust 2024 ban on
    // taking references to `static mut`.
    unsafe { ::core::ptr::read_volatile(p) }
}

/// Process manager IPC endpoint.
#[inline]
pub fn procmgr_ep() -> Cap {
    read(&raw const crate::__trona_cap_procmgr_ep)
}

/// VFS server IPC endpoint.
#[inline]
pub fn vfs_ep() -> Cap {
    read(&raw const crate::__trona_cap_vfs_ep)
}

/// Name service IPC endpoint.
#[inline]
pub fn namesrv_ep() -> Cap {
    read(&raw const crate::__trona_cap_namesrv_ep)
}

/// Per-thread POSIX signal notification.
#[inline]
pub fn signal_ntfn() -> Cap {
    read(&raw const crate::__trona_cap_signal_ntfn)
}

/// Resource server IPC endpoint.
#[inline]
pub fn rsrcsrv_ep() -> Cap {
    read(&raw const crate::__trona_cap_rsrcsrv_ep)
}

/// Console server IPC endpoint.
#[inline]
pub fn console_ep() -> Cap {
    read(&raw const crate::__trona_cap_console_ep)
}

/// Service readiness notification.
#[inline]
pub fn readiness_ntfn() -> Cap {
    read(&raw const crate::__trona_cap_readiness_ntfn)
}

/// Initrd device untyped.
#[inline]
pub fn initrd_untyped() -> Cap {
    read(&raw const crate::__trona_cap_initrd_untyped)
}

/// Framebuffer device untyped.
#[inline]
pub fn fb_untyped() -> Cap {
    read(&raw const crate::__trona_cap_fb_untyped)
}

/// PCI configuration space I/O port.
#[inline]
pub fn pci_ioport() -> Cap {
    read(&raw const crate::__trona_cap_pci_ioport)
}

/// COM1 serial I/O port.
#[inline]
pub fn com1_ioport() -> Cap {
    read(&raw const crate::__trona_cap_com1_ioport)
}

/// Process-local service endpoint.
#[inline]
pub fn service_ep() -> Cap {
    read(&raw const crate::__trona_cap_service_ep)
}

/// Win32 subsystem server IPC endpoint.
#[inline]
pub fn win32srv_ep() -> Cap {
    read(&raw const crate::__trona_cap_win32srv_ep)
}

/// Memory manager server IPC endpoint (delivered via `ROLE_MMSRV_CLIENT`).
#[inline]
pub fn mmsrv_ep() -> Cap {
    read(&raw const crate::__trona_cap_mmsrv_ep)
}

/// CSpace expansion notification (delivered via `AT_TRONA_CSPACE_NTFN`).
#[inline]
pub fn cspace_ntfn() -> Cap {
    read(&raw const crate::__trona_cspace_ntfn)
}

/// Main thread SchedContext slot (delivered via `AT_TRONA_SC_CAP`).
#[inline]
pub fn sc_cap() -> Cap {
    read(&raw const crate::__trona_sc_cap)
}

/// Next free CNode slot for runtime frame allocation
/// (delivered via `AT_TRONA_CSPACE_LAYOUT.frame_slot_base`).
#[inline]
pub fn next_frame_slot() -> Cap {
    read(&raw const crate::__trona_next_frame_slot)
}
