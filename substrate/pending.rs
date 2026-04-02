//! Pending request table for async server event loops.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides a fixed-size table for tracking deferred (split-phase) IPC
//! requests. Each entry captures the saved reply cap, receive slot, client
//! badge, and server-specific context needed to resume and eventually
//! reply to the original caller.
//!
//! Designed for `#![no_std]` single-threaded servers with no allocator.

/// Monotonically increasing request identifier for callback correlation.
pub type RequestId = u32;

/// Why a pending request is blocked, for observability and timeout logic.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WaitReason {
    /// Slot is free (not in use).
    Free = 0,
    /// Waiting for a downstream server to reply via callback.
    DownstreamCall = 1,
    /// Waiting for an async completion notification.
    AsyncCallback = 2,
    /// Waiting for a timer or timeout to fire.
    Timer = 3,
}

/// A single pending (deferred) request in a server's event loop.
///
/// Captures everything needed to resume and eventually reply to the
/// original client: the saved reply cap, the original badge/label for
/// dispatch, and the wait reason for observability.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingRequest {
    /// Whether this slot is in use (non-zero = active).
    pub active: u8,
    /// Why this request is waiting.
    pub wait_reason: WaitReason,
    /// Monotonically increasing request ID for matching callbacks.
    pub request_id: RequestId,
    /// CNode slot holding the saved reply cap (from cnode_save_caller).
    pub reply_slot: u64,
    /// CNode slot configured as receive slot for this request's cap transfer.
    pub recv_slot: u64,
    /// Badge of the original client (for routing the reply).
    pub client_badge: u64,
    /// Original request label (for context when resuming).
    pub orig_label: u64,
    /// Server-specific opaque context (4 words = 32 bytes).
    /// Each server interprets these differently:
    ///   - VFS inet: context[0] = conn_id, context[1] = op_type
    ///   - mmsrv:    context[0] = obj_type, context[1] = size_bits
    pub context: [u64; 4],
    /// Deadline in monotonic nanoseconds (0 = no timeout).
    pub deadline_ns: u64,
}

impl PendingRequest {
    pub const fn zeroed() -> Self {
        PendingRequest {
            active: 0,
            wait_reason: WaitReason::Free,
            request_id: 0,
            reply_slot: 0,
            recv_slot: 0,
            client_badge: 0,
            orig_label: 0,
            context: [0; 4],
            deadline_ns: 0,
        }
    }
}

/// Fixed-size table of pending requests for a single-threaded server.
///
/// `N` is the maximum number of concurrent deferred requests. Typical
/// values: 16 for VFS inet, 32 for VFS overall, 4 for mmsrv.
pub struct PendingTable<const N: usize> {
    entries: [PendingRequest; N],
    next_id: RequestId,
}

impl<const N: usize> PendingTable<N> {
    /// Create an empty table.
    pub const fn new() -> Self {
        PendingTable {
            entries: [PendingRequest::zeroed(); N],
            next_id: 1,
        }
    }

    /// Allocate a pending request slot. Returns the assigned RequestId,
    /// or 0 if the table is full.
    pub fn alloc(
        &mut self,
        reply_slot: u64,
        recv_slot: u64,
        client_badge: u64,
        orig_label: u64,
        wait_reason: WaitReason,
    ) -> RequestId {
        for entry in self.entries.iter_mut() {
            if entry.active == 0 {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                if self.next_id == 0 {
                    self.next_id = 1; // skip 0 (reserved for "no ID")
                }
                entry.active = 1;
                entry.wait_reason = wait_reason;
                entry.request_id = id;
                entry.reply_slot = reply_slot;
                entry.recv_slot = recv_slot;
                entry.client_badge = client_badge;
                entry.orig_label = orig_label;
                entry.context = [0; 4];
                entry.deadline_ns = 0;
                return id;
            }
        }
        0 // table full
    }

    /// Find a pending request by its ID. Returns a mutable reference, or
    /// None if not found.
    pub fn find_by_id(&mut self, id: RequestId) -> Option<&mut PendingRequest> {
        self.entries
            .iter_mut()
            .find(|e| e.active != 0 && e.request_id == id)
    }

    /// Find the first pending request matching a predicate on context.
    pub fn find_by<F>(&mut self, pred: F) -> Option<&mut PendingRequest>
    where
        F: Fn(&PendingRequest) -> bool,
    {
        self.entries
            .iter_mut()
            .find(|e| e.active != 0 && pred(e))
    }

    /// Complete (remove) a pending request by ID. Returns the entry if
    /// found, or None.
    pub fn complete(&mut self, id: RequestId) -> Option<PendingRequest> {
        for entry in self.entries.iter_mut() {
            if entry.active != 0 && entry.request_id == id {
                let result = *entry;
                *entry = PendingRequest::zeroed();
                return Some(result);
            }
        }
        None
    }

    /// Complete (remove) a pending request by badge and context match.
    /// Uses context[0] and context[1] for matching (conn_id + op_type pattern).
    pub fn complete_by_context(&mut self, ctx0: u64, ctx1: u64) -> Option<PendingRequest> {
        for entry in self.entries.iter_mut() {
            if entry.active != 0 && entry.context[0] == ctx0 && entry.context[1] == ctx1 {
                let result = *entry;
                *entry = PendingRequest::zeroed();
                return Some(result);
            }
        }
        None
    }

    /// Number of active entries.
    pub fn count(&self) -> usize {
        self.entries.iter().filter(|e| e.active != 0).count()
    }

    /// Whether the table has any free slots.
    pub fn has_capacity(&self) -> bool {
        self.entries.iter().any(|e| e.active == 0)
    }

    /// Iterate over all active entries (immutable).
    pub fn iter_active(&self) -> impl Iterator<Item = &PendingRequest> {
        self.entries.iter().filter(|e| e.active != 0)
    }

    /// Get entry at a raw index (for dump/debug). Returns None if index
    /// is out of bounds or the slot is inactive.
    pub fn get(&self, index: usize) -> Option<&PendingRequest> {
        self.entries.get(index).filter(|e| e.active != 0)
    }

    /// Find the nearest deadline among active entries. Returns u64::MAX
    /// if no entries have a deadline set.
    pub fn nearest_deadline(&self) -> u64 {
        let mut min = u64::MAX;
        for entry in &self.entries {
            if entry.active != 0 && entry.deadline_ns != 0 && entry.deadline_ns < min {
                min = entry.deadline_ns;
            }
        }
        min
    }

    /// Table capacity (compile-time constant).
    pub const fn capacity(&self) -> usize {
        N
    }
}
