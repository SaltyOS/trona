// SPDX-License-Identifier: GPL-2.0-only
//
//! trona_server — server-loop primitives shared across every
//! userland server (init / namesrv / rsrcsrv / mmsrv / vfs /
//! dnssrv / netsrv / posix_ttysrv / win32_csrss).
//!
//! Eleven primitives sit here:
//!
//! * [`EventLoop`] — `EQ_WAIT → cookie demux → MP_READ →
//!   dispatch` loop with stable-index `CookieTable<T>` storage.
//! * [`ContinuationArena<C>`] — token-keyed store of suspended async
//!   continuations: park the state needed to finish a non-blocking
//!   cross-server request, keyed by the correlation token the reply
//!   echoes, and take it when the reply lands on the reactor.
//! * [`OutboundQueue`] — retain-on-`WouldBlock` send queue: a reply or
//!   one-way notify whose target ring is momentarily full is retained
//!   and replayed when the peer's `STATE_WRITABLE` fires, so the reactor
//!   never blocks on a back-pressured send.
//! * [`SegmentedArray<T>`] — non-moving segment-backed index array
//!   that the cookie table and any other server arena layer over.
//!   Generic, allocator-injected — never panics on grow because the
//!   caller provides the segment backing.
//! * [`slab`] — page-backed [`TrackedSlab`] + [`BaseSortedIndex`] with
//!   explicit, threaded [`PageBacking`] freeing (vs `SegmentedArray`'s
//!   append-only allocator). The per-client / per-arena reclaimable
//!   storage layer for mmsrv and init, keyed by stable [`SlabId`].
//! * [`FrameAllocator`] — untyped-backed child allocator: retypes
//!   FRAME / MO / Watch objects from a pool of adopted untyped chunks
//!   and recycles an exhausted chunk once every child cap has been
//!   revoked. The freeing engine each server's [`PageBacking`] drives.
//! * [`U32HashIndex`] — growable, heap-free `u32 → u32` open-addressed
//!   hash (backshift deletion, Fibonacci scatter). The O(1) exact-key
//!   companion to [`BaseSortedIndex`]; init's `client_id → pid` map.
//! * [`RecvSlotArena`] — per-service receive-slot pool that
//!   recycles a CNode slot per server-loop iteration and grows new
//!   segments through an injected slot allocator.
//! * [`FixedRecvWindow`] — common manager for bootstrap-reserved
//!   receive scratch windows that must be cleared and re-armed
//!   between reactor iterations.
//! * [`capture_transferred_cap`] — cap_count-trust helper that
//!   reads `ipc_buffer.reserved[KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT]`
//!   and tells the caller whether a kept cap actually arrived.
//! * [`ReplyLease`] — single-consume RAII guard for saved reply
//!   endpoints; explicit `consume / cancel / park / disarm`
//!   transitions, debug-only Drop trap on `Active`.
//!
//! Strict layering: depends only on `trona_kernel` (and the
//! kernel-published `uapi` underneath). Never reaches into
//! `trona_runtime` — the `SlotAllocator` callbacks are the
//! injection seam that lets the runtime drive the server primitive
//! without forming a backwards edge in the dependency graph.

#![no_std]
#![allow(clippy::missing_safety_doc)]

pub mod badge;
pub mod continuation;
pub mod event_loop;
pub mod frame_alloc;
pub mod hash_index;
pub mod outbound;
pub mod recv_slot;
pub mod reply;
pub mod segmented_array;
pub mod slab;

pub use continuation::{ContHandle, ContinuationArena};
pub use event_loop::{
    CookieEntry, CookieTable, EqDispatcher, EventLoop, MpReadMeta, decode_cookie, encode_cookie,
};
pub use frame_alloc::{Chunk, FrameAllocator, MAX_CHUNKS};
pub use hash_index::U32HashIndex;
pub use outbound::{OUTBOUND_INLINE_WORDS, OutboundKind, OutboundQueue, OutboundResult};
pub use recv_slot::{
    FixedRecvWindow, RecvSlotArena, SlotAllocConsecutive, SlotAllocator, SlotInvokeDepth,
    arm_fixed_recv_window, capture_transferred_cap, clear_fixed_recv_window,
};
pub use reply::{
    MpReplyTarget, ParkedReply, ReplyConsumeResult, ReplyLease, ReplyLeaseState, mp_write_reply_to,
    mp_write_reply_to_with_error_fallback,
};
pub use segmented_array::{SegError, SegmentAllocator, SegmentedArray};
pub use slab::{
    BaseSortedIndex, IndexEntry, IndexIter, PageBacking, ReservationKind, SlabId, SlabIter,
    TrackedBuffer, TrackedSlab,
};
