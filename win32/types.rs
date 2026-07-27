// SPDX-License-Identifier: GPL-2.0-only
//
//! Kernel ABI return shape and userland IPC wrap types for the
//! PE-target kernel32.dll.
//!
//! These mirror substrate's `core_types::{TronaMsg, IpcContext,
//! TronaResult}` exactly (`#[repr(C)]`) because PE-target kernel32
//! cannot link against the saltyos-target substrate rmeta. The kernel-
//! mapped IPC buffer is `uapi::kernite_ipc_buffer` (bindgen output);
//! substrate and kernel32 share that one type across the two rustc
//! target spec rebuilds of the `uapi` crate, with no intermediate
//! `IpcBuffer` alias.

/// Result of a raw kernite syscall: `error` is `KERNITE_OK` (0) on
/// success, otherwise a `KERNITE_ERR_*` code. `value` carries the
/// payload register from the trap.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaResult {
    pub error: u64,
    pub value: u64,
}

/// Userland IPC message — staging shape that kernel32 fills before
/// invoking `MP_CALL`. Layout matches substrate's `TronaMsg`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaMsg {
    pub label: u64,
    pub length: u64,
    pub regs: [u64; 32],
}

impl TronaMsg {
    pub const fn zeroed() -> Self {
        TronaMsg {
            label: 0,
            length: 0,
            regs: [0; 32],
        }
    }
}

/// Per-thread IPC context: pointer to the kernel-mapped IPC buffer
/// page and the count of caps staged for the next send. Layout
/// matches substrate's `IpcContext`.
#[repr(C)]
pub struct IpcContext {
    pub ipc_buffer: *mut uapi::kernite_ipc_buffer,
    pub send_cap_count: i32,
}

unsafe impl Sync for IpcContext {}
unsafe impl Send for IpcContext {}

impl IpcContext {
    pub const fn new() -> Self {
        IpcContext {
            ipc_buffer: core::ptr::null_mut(),
            send_cap_count: 0,
        }
    }
}
