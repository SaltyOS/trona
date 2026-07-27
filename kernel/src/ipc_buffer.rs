//! Userland-side accessors for the per-thread IPC buffer mapped at
//! the TCB's `ipc_buffer` slot. Knows the kernel's reserved-area
//! layout (see `kernite/include/uapi/ipc.h`).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use uapi::{
    KERNITE_IPC_RESERVED_EVENT_RECORD_BASE, KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT,
    kernite_event_record, kernite_ipc_buffer,
};

/// Read the EventRecord the kernel published into the buffer's
/// reserved area on the most recent successful `KERNITE_INV_EQ_WAIT`
/// / `KERNITE_INV_EQ_POLL`.
///
/// The kernel writes the record's wire layout (kind:u32, status:u32,
/// cookie:u64, ...) starting at
/// `reserved[KERNITE_IPC_RESERVED_EVENT_RECORD_BASE]`, which matches
/// `kernite_event_record`'s byte layout exactly. The read goes
/// through `read_unaligned` so the caller does not need to sync
/// alignment with the kernel writer.
///
/// # Safety
/// `buf` must point to the calling thread's IPC buffer (mapped read-
/// write into the current process by the kernel). The buffer's
/// contents must not race with another thread / interrupt mutation
/// for the duration of this call. The most recent EQ_WAIT/EQ_POLL
/// must have returned success — calling this after a failed wait
/// yields stale or zero-filled data.
pub unsafe fn read_event_record(buf: *const kernite_ipc_buffer) -> kernite_event_record {
    unsafe {
        let base = (*buf)
            .reserved
            .as_ptr()
            .add(KERNITE_IPC_RESERVED_EVENT_RECORD_BASE as usize);
        core::ptr::read_unaligned(base as *const kernite_event_record)
    }
}

/// Read the kernel-published `received_cap_count` from the buffer's
/// reserved area. This is the number of caps the kernel installed
/// into `caps[]` on the most recent inbound IPC. Regular MP_CALL
/// requests only carry user-supplied caps; no implicit reply cap
/// is appended.
///
/// # Safety
/// `buf` must point to the calling thread's IPC buffer. The most
/// recent MP_READ / MP_CALL must have returned success.
pub unsafe fn read_received_cap_count(buf: *const kernite_ipc_buffer) -> u64 {
    unsafe {
        let slot = (*buf)
            .reserved
            .as_ptr()
            .add(KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT as usize);
        core::ptr::read_volatile(slot)
    }
}
