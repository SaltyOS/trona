// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-thread wakeup plumbing — `EventQueue` + `Timer` + signal pipe
//! `Watch`.
//!
//! POSIX timing primitives (`nanosleep`, `usleep`, `sleep`) and the
//! cooperative signal-arrival check (`signals::posix_sigcheck`) both
//! consume from the calling thread's own `EventQueue`. Records arrive
//! from two producers:
//!
//! - **Timer expiry** — `KERNITE_INV_TIMER_SET` arms the thread's own
//!   `Timer` bound to the wakeup EQ. Sleep paths tag their record
//!   with `WAKEUP_COOKIE_TIMER` so the dispatch loop can recognise
//!   the wake reason.
//!
//! - **Signal arrival** — the spawner (init) writes signal records
//!   into the per-process signal `MessagePipe`
//!   (`trona_runtime::client::caps::signal_pipe()`); a one-shot `Watch` per thread
//!   bridges the pipe's `KERNITE_STATE_READABLE` transitions into the
//!   thread's wakeup EQ, tagged `WAKEUP_COOKIE_SIGNAL_PIPE`. The
//!   dispatch loop drains the pipe into `__sig_pending_bits`, calls
//!   back into the signal layer, then re-arms the Watch (Watch
//!   semantics are one-shot edge — see
//!   `kernite/src/event/watch.rs`).
//!
//! All three kernel objects are retyped lazily on first use against
//! the calling thread's `PosixThreadExt`. Before TLS is active (very
//! early CRT bring-up, before `pthread_setup_main`) the helpers fall
//! back to a small process-wide pair so the very first sleep / signal
//! check still works.

use core::sync::atomic::Ordering;

use trona_runtime::core::slot_alloc::{OwnedCap, alloc_object, slot_invoke_depth};
use trona_runtime::thread::sync::Mutex;

use crate::pthread::current_ext_ptr;

/// Cookie distinguishing a timer-expiry record on a thread's wakeup
/// EQ.
pub const WAKEUP_COOKIE_TIMER: u64 = 0xCAFE_0001;
/// Cookie distinguishing a signal-pipe-readable record on a thread's
/// wakeup EQ. `WATCH_REGISTER` stamps every record it produces with
/// this value.
pub const WAKEUP_COOKIE_SIGNAL_PIPE: u64 = 0xCAFE_0002;

/// EventQueue depth (log2). 16 slots is enough for sleep + signal
/// records without back-pressure during normal operation; the only
/// realistic overflow path is a runaway signal flood, which the
/// kernel itself folds into a single `EVENT_TYPE_OVERFLOW` record.
const WAKEUP_EQ_DEPTH_BITS: u64 = 4;

// ---------------------------------------------------------------------------
// Pre-TLS fallback (used until `pthread_setup_main` publishes the main
// thread's `ThreadDesc` and `current_ext_ptr()` starts returning a
// real `PosixThreadExt`). Once TLS is active, wakeup state lives on
// the per-thread `PosixThreadExt`.
// ---------------------------------------------------------------------------

// Pre-TLS fallback caps. Accessed only while FALLBACK_LOCK is held.
// `static mut` is required because OwnedCap is !Sync; FALLBACK_LOCK
// provides the mutual exclusion that makes this sound.
static mut FALLBACK_EQ: Option<OwnedCap> = None;
static mut FALLBACK_TIMER: Option<OwnedCap> = None;
static mut FALLBACK_WATCH: Option<OwnedCap> = None;
static FALLBACK_LOCK: Mutex = Mutex::new();

/// Adopt a raw slot returned by `alloc_object` into an `OwnedCap`.
#[inline]
fn adopt(slot: u64) -> OwnedCap {
    // SAFETY: slot was just allocated by alloc_object and is uniquely owned.
    unsafe { OwnedCap::from_raw(slot, slot_invoke_depth(slot)) }
}

/// Decoded layout of an `EventRecord` as written into the IPC buffer
/// by `EQ_WAIT` / `EQ_POLL`. Mirrors `kernite_event_record` from
/// `kernite/include/uapi/event.h`.
#[derive(Clone, Copy, Default)]
pub struct WakeupRecord {
    pub kind: u32,
    pub status: u32,
    pub cookie: u64,
    pub object_id: u64,
    pub state_set: u64,
    pub state_seen: u64,
    pub payload0: u64,
    pub payload1: u64,
    pub payload2: u64,
}

/// Read the event record the kernel left in the current thread's IPC
/// buffer following a successful `EQ_WAIT` / `EQ_POLL`. Delegates to
/// `trona_kernel::ipc_buffer::read_event_record` so the wire layout
/// (currently `reserved[KERNITE_IPC_RESERVED_EVENT_RECORD_BASE..]`)
/// stays in one place.
unsafe fn read_event_record_from_ipc() -> WakeupRecord {
    unsafe {
        let ctx = crate::tls::current_ipc_ctx();
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            return WakeupRecord::default();
        }
        let raw = trona_kernel::ipc_buffer::read_event_record((*ctx).ipc_buffer);
        WakeupRecord {
            kind: raw.kind,
            status: raw.status,
            cookie: raw.cookie,
            object_id: raw.object_id,
            state_set: raw.state_set,
            state_seen: raw.state_seen,
            payload0: raw.payload0,
            payload1: raw.payload1,
            payload2: raw.payload2,
        }
    }
}

/// Lazily retype the calling thread's wakeup `EventQueue`. Returns the
/// raw cap address (for passing to `syscall::invoke`) on success.
fn ensure_wakeup_eq() -> Option<u64> {
    let ext = current_ext_ptr();
    unsafe {
        if !ext.is_null() {
            // Fast path: per-thread slot already allocated.
            if let Some(ref cap) = (*ext).wakeup_eq {
                return Some(cap.borrow().addr());
            }
            // Slow path: allocate under FALLBACK_LOCK (guards alloc_object
            // reentrancy; per-thread field is only written here by the owning
            // thread, but the lock serialises concurrent alloc_object calls).
            FALLBACK_LOCK.lock();
            if let Some(ref cap) = (*ext).wakeup_eq {
                FALLBACK_LOCK.unlock();
                return Some(cap.borrow().addr());
            }
            let slot =
                match alloc_object(uapi::KERNITE_OBJ_EVENT_QUEUE as u64, WAKEUP_EQ_DEPTH_BITS) {
                    Ok(s) => s,
                    Err(_) => {
                        FALLBACK_LOCK.unlock();
                        return None;
                    }
                };
            let addr = slot;
            (*ext).wakeup_eq = Some(adopt(slot));
            FALLBACK_LOCK.unlock();
            Some(addr)
        } else {
            // Pre-TLS fallback path: FALLBACK_LOCK is mandatory.
            FALLBACK_LOCK.lock();
            if let Some(ref cap) = *(&raw const FALLBACK_EQ) {
                let addr = cap.borrow().addr();
                FALLBACK_LOCK.unlock();
                return Some(addr);
            }
            let slot =
                match alloc_object(uapi::KERNITE_OBJ_EVENT_QUEUE as u64, WAKEUP_EQ_DEPTH_BITS) {
                    Ok(s) => s,
                    Err(_) => {
                        FALLBACK_LOCK.unlock();
                        return None;
                    }
                };
            let addr = slot;
            *(&raw mut FALLBACK_EQ) = Some(adopt(slot));
            FALLBACK_LOCK.unlock();
            Some(addr)
        }
    }
}

/// Lazily retype the calling thread's sleep `Timer`. The bind to the
/// wakeup EQ is established at every `TIMER_SET` rather than once
/// here, so the same Timer can be re-armed without re-binding.
fn ensure_sleep_timer() -> Option<u64> {
    let ext = current_ext_ptr();
    unsafe {
        if !ext.is_null() {
            if let Some(ref cap) = (*ext).sleep_timer {
                return Some(cap.borrow().addr());
            }
            FALLBACK_LOCK.lock();
            if let Some(ref cap) = (*ext).sleep_timer {
                FALLBACK_LOCK.unlock();
                return Some(cap.borrow().addr());
            }
            let slot = match alloc_object(uapi::KERNITE_OBJ_TIMER as u64, 0) {
                Ok(s) => s,
                Err(_) => {
                    FALLBACK_LOCK.unlock();
                    return None;
                }
            };
            let addr = slot;
            (*ext).sleep_timer = Some(adopt(slot));
            FALLBACK_LOCK.unlock();
            Some(addr)
        } else {
            FALLBACK_LOCK.lock();
            if let Some(ref cap) = *(&raw const FALLBACK_TIMER) {
                let addr = cap.borrow().addr();
                FALLBACK_LOCK.unlock();
                return Some(addr);
            }
            let slot = match alloc_object(uapi::KERNITE_OBJ_TIMER as u64, 0) {
                Ok(s) => s,
                Err(_) => {
                    FALLBACK_LOCK.unlock();
                    return None;
                }
            };
            let addr = slot;
            *(&raw mut FALLBACK_TIMER) = Some(adopt(slot));
            FALLBACK_LOCK.unlock();
            Some(addr)
        }
    }
}

/// Arm (or re-arm) the calling thread's one-shot `Watch` so the
/// signal pipe's next `STATE_READABLE` transition enqueues a record
/// tagged with [`WAKEUP_COOKIE_SIGNAL_PIPE`] into `eq`. `Watch` is
/// one-shot edge-triggered (see `kernite/src/event/watch.rs`); each
/// successful drain consumes the arming, so the dispatch loop calls
/// this helper after every signal-pipe record is processed.
fn arm_signal_watch(eq: u64) -> Result<(), ()> {
    let signal_pipe = trona_runtime::client::caps::signal_pipe();
    if signal_pipe.is_null() {
        // No spawner-attached signal pipe → no signal channel for
        // this process. Sleep / sigcheck still work; they just never
        // observe a signal record.
        return Ok(());
    }
    let ext = current_ext_ptr();
    let watch = unsafe {
        if !ext.is_null() {
            // Fast path: Watch already allocated for this thread.
            if let Some(ref cap) = (*ext).signal_watch {
                cap.borrow().addr()
            } else {
                FALLBACK_LOCK.lock();
                if let Some(ref cap) = (*ext).signal_watch {
                    let addr = cap.borrow().addr();
                    FALLBACK_LOCK.unlock();
                    addr
                } else {
                    let slot = match alloc_object(uapi::KERNITE_OBJ_WATCH as u64, 0) {
                        Ok(s) => s,
                        Err(_) => {
                            FALLBACK_LOCK.unlock();
                            return Err(());
                        }
                    };
                    let addr = slot;
                    (*ext).signal_watch = Some(adopt(slot));
                    FALLBACK_LOCK.unlock();
                    addr
                }
            }
        } else {
            FALLBACK_LOCK.lock();
            if let Some(ref cap) = *(&raw const FALLBACK_WATCH) {
                let addr = cap.borrow().addr();
                FALLBACK_LOCK.unlock();
                addr
            } else {
                let slot = match alloc_object(uapi::KERNITE_OBJ_WATCH as u64, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        FALLBACK_LOCK.unlock();
                        return Err(());
                    }
                };
                let addr = slot;
                *(&raw mut FALLBACK_WATCH) = Some(adopt(slot));
                FALLBACK_LOCK.unlock();
                addr
            }
        }
    };
    let arm = trona_kernel::syscall::invoke(
        watch,
        uapi::KERNITE_INV_WATCH_REGISTER as u64,
        signal_pipe.addr(),
        eq,
        uapi::KERNITE_STATE_READABLE as u64,
        WAKEUP_COOKIE_SIGNAL_PIPE,
    );
    if arm.error != 0 { Err(()) } else { Ok(()) }
}

/// Consume a single ready signal record from the per-process signal
/// `MessagePipe`. Caller invariant: the wakeup EQ has just delivered
/// a record tagged with [`WAKEUP_COOKIE_SIGNAL_PIPE`], so the pipe is
/// guaranteed readable — a single `MP_READ` returns the queued record
/// without blocking.
///
/// Wire format: init writes `record.words[0] = signum`, which the
/// kernel surfaces in IPC `msg[2]` (msg[0] is the record label,
/// msg[1] the length, msg[2..] the per-record words[]). Returns 1 if
/// a signal bit was folded into `__sig_pending_bits`, 0 otherwise.
pub fn drain_signal_pipe() -> usize {
    let signal_pipe = trona_runtime::client::caps::signal_pipe();
    if signal_pipe.is_null() {
        return 0;
    }
    let ctx = crate::tls::current_ipc_ctx();
    if ctx.is_null() {
        return 0;
    }

    let r = trona_kernel::syscall::invoke(
        signal_pipe.addr(),
        uapi::KERNITE_INV_MP_READ as u64,
        0,
        0,
        0,
        0,
    );
    if r.error != 0 {
        return 0;
    }
    unsafe {
        if (*ctx).ipc_buffer.is_null() {
            return 0;
        }
        let signum = (*(*ctx).ipc_buffer).msg[2] & 0x3F;
        if signum > 0 && signum < crate::NSIG as u64 {
            crate::__sig_pending_bits.fetch_or(1u64 << signum, Ordering::AcqRel);
            return 1;
        }
    }
    0
}

/// Block in `EQ_WAIT` until the calling thread's wakeup EQ produces
/// the next record. Returns the decoded record on success, `None` if
/// the wait was cancelled (`KERNITE_ERR_CANCELLED`) or the queue is
/// unreachable. The signal-pipe Watch is (re-)armed on every entry so
/// the next pipe write reaches this thread's EQ.
pub fn wait_record() -> Option<WakeupRecord> {
    let eq = ensure_wakeup_eq()?;
    let _ = arm_signal_watch(eq);
    let r = trona_kernel::syscall::invoke(
        eq,
        uapi::KERNITE_INV_EQ_WAIT as u64,
        trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        0,
        0,
        0,
    );
    if r.error != 0 {
        return None;
    }
    Some(unsafe { read_event_record_from_ipc() })
}

/// Non-blocking variant of [`wait_record`]. Returns `Some(record)`
/// when a record was available, `None` when the queue was empty.
pub fn poll_record() -> Option<WakeupRecord> {
    let eq = ensure_wakeup_eq()?;
    let _ = arm_signal_watch(eq);
    let r = trona_kernel::syscall::invoke(eq, uapi::KERNITE_INV_EQ_POLL as u64, 0, 0, 0, 0);
    if r.error != 0 || r.value == 0 {
        return None;
    }
    Some(unsafe { read_event_record_from_ipc() })
}

/// Arm the calling thread's sleep timer to fire at the absolute
/// monotonic deadline `deadline_ns`, posting the expiry record into
/// the thread's wakeup EQ tagged with [`WAKEUP_COOKIE_TIMER`].
/// Returns 0 on success, -1 on retype / invocation failure.
pub fn arm_sleep_timer(deadline_ns: u64) -> i32 {
    let eq = match ensure_wakeup_eq() {
        Some(eq) => eq,
        None => return -1,
    };
    let timer = match ensure_sleep_timer() {
        Some(t) => t,
        None => return -1,
    };
    let r = trona_kernel::syscall::invoke(
        timer,
        uapi::KERNITE_INV_TIMER_SET as u64,
        deadline_ns,
        0,
        eq,
        WAKEUP_COOKIE_TIMER,
    );
    if r.error != 0 { -1 } else { 0 }
}

/// Cancel any in-flight sleep timer arming on the calling thread's
/// timer. Idempotent.
pub fn cancel_sleep_timer() {
    let ext = current_ext_ptr();
    let timer = unsafe {
        if !ext.is_null() {
            (*ext)
                .sleep_timer
                .as_ref()
                .map(|c| c.borrow().addr())
                .unwrap_or(0)
        } else {
            // Pre-TLS: read under lock; cancel is a best-effort fire-and-forget.
            FALLBACK_LOCK.lock();
            let addr = (&*(&raw const FALLBACK_TIMER))
                .as_ref()
                .map(|c| c.borrow().addr())
                .unwrap_or(0);
            FALLBACK_LOCK.unlock();
            addr
        }
    };
    if timer == 0 {
        return;
    }
    let _ = trona_kernel::syscall::invoke(timer, uapi::KERNITE_INV_TIMER_CANCEL as u64, 0, 0, 0, 0);
}

/// Reset the calling thread's wakeup state after `fork`. The child
/// inherits a COW copy of the parent's address space, so the
/// `Option<OwnedCap>` values look valid but the cap slots they
/// reference are stale — the child's CSpace is a clone of the
/// parent's at fork time, and the EQ/Timer/Watch caps were never
/// transferred. Suppress Drop via `forget` on each so the child does
/// not issue bogus `cnode_delete` calls against the cloned slots.
/// The next sleep / signal check will lazy-retype fresh objects.
pub fn reset_after_fork() {
    let ext = current_ext_ptr();
    if !ext.is_null() {
        unsafe {
            core::mem::forget((*ext).wakeup_eq.take());
            core::mem::forget((*ext).sleep_timer.take());
            core::mem::forget((*ext).signal_watch.take());
        }
    }
    // FALLBACK_LOCK is single-threaded post-fork; no need to lock.
    unsafe {
        core::mem::forget((&raw mut FALLBACK_EQ as *mut Option<OwnedCap>).replace(None));
        core::mem::forget((&raw mut FALLBACK_TIMER as *mut Option<OwnedCap>).replace(None));
        core::mem::forget((&raw mut FALLBACK_WATCH as *mut Option<OwnedCap>).replace(None));
    }
}
