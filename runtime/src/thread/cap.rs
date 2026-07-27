// SPDX-License-Identifier: GPL-2.0-only
//
//! Owned capability handles for the thread subsystem.
//!
//! [`ThreadDesc`](super::tls::ThreadDesc) stores a thread's kernel-object
//! capabilities, and their ownership is *conditional*: the main thread borrows
//! well-known slots (`CAP_SELF_TCB`, the role `SchedContext`) that the process
//! never releases, while a spawned worker owns freshly retyped slots that are
//! torn down when the thread is reaped. These two types make that distinction
//! explicit and compiler-checked — a `Borrowed` slot can never be accidentally
//! freed, and an `Owned` slot is released exactly once on teardown.
//!
//! The fork child is the one path that must give up owned slots *without*
//! releasing them (the slot indices are stale COW copies): it calls
//! [`ThreadCap::forget`] / [`OwnedSlotRange::forget`] instead of dropping.

use crate::core::slot_alloc::{self, OwnedCap, SlotOrigin};
use trona_kernel::core_types::{Cap, CapRef};

/// A single capability slot held in a [`ThreadDesc`](super::tls::ThreadDesc).
pub(crate) enum ThreadCap {
    /// No capability installed — an unused descriptor field, or an
    /// mmsrv-backed worker whose objects live in init's CSpace, not ours.
    None,
    /// A slot this thread owns; released (delete + free) on drop.
    Owned(OwnedCap),
    /// A borrowed slot — the main thread's `CAP_SELF_TCB` / role
    /// `SchedContext`. Never released.
    Borrowed(CapRef),
}

impl ThreadCap {
    /// Borrow a process-lifetime slot (the main thread's `CAP_SELF_TCB` /
    /// role `SchedContext`). Dropping it never releases the slot.
    pub(crate) fn borrowed(cap: CapRef) -> Self {
        ThreadCap::Borrowed(cap)
    }

    /// Give up the cap *without* releasing it, leaving the field `None`. Used
    /// only in the fork child, where the slot index is a stale COW copy that
    /// must not be deleted.
    pub(crate) fn forget(&mut self) {
        core::mem::forget(core::mem::replace(self, ThreadCap::None));
    }
}

/// A consecutively allocated run of capability slots this thread owns — the
/// stack / TLS frame caps.
///
/// Models the *allocation*, not the fills: on drop every slot in
/// `[base, base + count)` is delete-and-freed at `base`'s invoke
/// depth. A run that was only partially retyped (spawn failure mid-loop) is
/// handled for free: deleting an unfilled slot is a no-op and the whole run's
/// allocator ownership is released.
pub(crate) struct OwnedSlotRange {
    base: Cap,
    count: u64,
    depth: u8,
    origin: SlotOrigin,
}

impl OwnedSlotRange {
    /// Adopt a consecutive run with an explicit [`SlotOrigin`] — used when the
    /// run was allocated from a private [`SlotPool`] (`SlotOrigin::Pool`), so
    /// drop deletes each cap without returning its index to `slot_alloc`.
    ///
    /// # Safety
    /// - `[base, base + count)` is a consecutive run of slots the caller owns
    ///   exclusively; on drop each slot is torn down and (for
    ///   `SlotOrigin::Global`) returned to `slot_alloc` exactly once. No other
    ///   owner may free any slot in the run.
    /// - `origin` matches where the run was allocated.
    pub(crate) unsafe fn from_consecutive_in(base: Cap, count: u64, origin: SlotOrigin) -> Self {
        OwnedSlotRange {
            base,
            count,
            depth: slot_alloc::slot_invoke_depth(base),
            origin,
        }
    }

    /// The raw slot index of element `p` — for staging a retype destination
    /// (a destination slot is an index, not a capability).
    pub(crate) fn slot_at(&self, p: u64) -> Cap {
        self.base + p
    }

    /// Borrow element `p` as a [`CapRef`] for an invocation (e.g. the frame
    /// capability passed to `vspace_map`).
    pub(crate) fn borrow_at(&self, p: u64) -> CapRef {
        CapRef::at_depth(self.base + p, self.depth)
    }

    /// Give up the run *without* releasing it (fork child: stale COW slots).
    pub(crate) fn forget(self) {
        core::mem::forget(self);
    }
}

impl Drop for OwnedSlotRange {
    fn drop(&mut self) {
        let mut p = 0;
        while p < self.count {
            // SAFETY: this range is the sole owner of every slot in
            // `[base, base + count)` at `self.depth` (the unsafe
            // `from_consecutive_in` constructor asserted exclusive ownership of
            // the run); this drop is their single teardown.
            match self.origin {
                SlotOrigin::Global => unsafe {
                    slot_alloc::delete_and_free_depth(self.base + p, self.depth)
                },
                SlotOrigin::Pool => unsafe { slot_alloc::delete_depth(self.base + p, self.depth) },
            }
            p += 1;
        }
    }
}
