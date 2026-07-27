//! Synchronization primitives: Mutex, Condvar, RWLock, Barrier, Semaphore, Once
//!
//! Subsystem-neutral, futex-based userspace synchronization. No kernel
//! objects are consumed — every primitive is a single atomic word plus
//! `futex_wait`/`futex_wake` syscalls on contention.
//!
//! This module intentionally returns substrate-level status codes
//! (`TRONA_OK`, `TRONA_BUSY`, `TRONA_DEADLOCK`, `TRONA_TIMED_OUT`,
//! `TRONA_INVALID_OPERATION`) rather than any particular subsystem's error
//! numbering. Each personality layer converts these into its own error
//! surface (POSIX errno, NT status, etc.).
//!
//! # Cancellation
//!
//! Blocking primitives (`Condvar::wait`, typed variants) observe a
//! `cancel_pending` flag on the current thread's TLS block and invoke
//! a runtime-installed hook if set. Subsystems that support cancellation
//! install the hook via `install_cancel_hook()`. If no hook is installed,
//! cancellation is a no-op — suitable for bare services that have no
//! cancellation concept.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use trona_kernel::syscall::{
    futex_wait as sys_futex_wait, futex_wait_timeout as sys_futex_wait_timeout,
    futex_wake as sys_futex_wake,
};
use trona_protocol::common::{
    TRONA_BUSY, TRONA_DEADLOCK, TRONA_INVALID_OPERATION, TRONA_OK, TRONA_TIMED_OUT,
};

static MUTEX_SLOWPATH_COUNT: AtomicU64 = AtomicU64::new(0);
static FUTEX_WAIT_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
static FUTEX_WAKE_CALL_COUNT: AtomicU64 = AtomicU64::new(0);

#[inline]
fn futex_wait(addr: *const u32, expected: u32) -> u64 {
    FUTEX_WAIT_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    sys_futex_wait(addr, expected)
}

#[inline]
fn futex_wait_timeout(addr: *const u32, expected: u32, timeout_ns: u64) -> u64 {
    FUTEX_WAIT_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    sys_futex_wait_timeout(addr, expected, timeout_ns)
}

#[inline]
fn futex_wake(addr: *const u32, count: u32) -> u64 {
    FUTEX_WAKE_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    sys_futex_wake(addr, count)
}

#[inline]
fn note_mutex_slowpath() {
    MUTEX_SLOWPATH_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn debug_lock_stats() -> (u64, u64, u64) {
    (
        MUTEX_SLOWPATH_COUNT.load(Ordering::Relaxed),
        FUTEX_WAIT_CALL_COUNT.load(Ordering::Relaxed),
        FUTEX_WAKE_CALL_COUNT.load(Ordering::Relaxed),
    )
}

#[inline]
fn monotonic_now_ns() -> u64 {
    trona_kernel::syscall::clock_read_monotonic(crate::client::caps::clock_cap().addr())
}

#[inline]
fn remaining_timeout_ns(deadline_ns: u64) -> u64 {
    deadline_ns.saturating_sub(monotonic_now_ns())
}

/// Record the futex address we're about to block on (for cancellation wake).
/// pthread_cancel() reads this to wake threads blocked at cancellation points.
#[inline]
fn set_blocked_futex(addr: *const u32) {
    if let Some(tls) = crate::thread::tls::current_tls() {
        // SAFETY: tls is a valid pointer to the current thread's TLS block
        unsafe {
            (*tls)
                .blocked_futex_addr
                .store(addr as u64, Ordering::Release);
        }
    }
}

/// Clear the blocked futex address after returning from futex_wait.
#[inline]
fn clear_blocked_futex() {
    if let Some(tls) = crate::thread::tls::current_tls() {
        // SAFETY: tls is a valid pointer to the current thread's TLS block
        unsafe {
            (*tls).blocked_futex_addr.store(0, Ordering::Release);
        }
    }
}

// =========================================================================
// Cancellation hook (subsystem-neutral)
// =========================================================================

/// Cancellation callback pointer. `0` means no hook installed.
///
/// Stored as `usize` because `AtomicPtr<fn()>` is painful in no_std contexts.
/// Cast back to `unsafe fn()` via `core::mem::transmute` when invoking.
static CANCEL_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install a cancellation callback into the substrate sync layer.
///
/// The hook is called by blocking primitives (`Condvar::wait` and its
/// variants) after they observe a `cancel_pending` flag on the current
/// thread's TLS block. Subsystems that implement thread cancellation
/// install a hook that performs their cleanup and exit protocol.
///
/// # Safety
///
/// `hook` must remain a valid function pointer for the lifetime of the
/// process. Typically installed once during subsystem init and never
/// replaced.
pub unsafe fn install_cancel_hook(hook: unsafe fn()) {
    CANCEL_HOOK.store(hook as usize, Ordering::Release);
}

/// Run the installed cancellation hook if `cancel_pending` is set on the
/// current thread. No-op if no hook is installed.
fn check_cancellation() {
    if let Some(tls) = crate::thread::tls::current_tls() {
        unsafe {
            let pending = ::core::ptr::read_volatile(&raw const (*tls).cancel_pending);
            if pending != 0 && (*tls).cancel_state == 0 {
                let hook_addr = CANCEL_HOOK.load(Ordering::Acquire);
                if hook_addr != 0 {
                    let f: unsafe fn() = core::mem::transmute(hook_addr);
                    f();
                }
            }
        }
    }
}

// =========================================================================
// Mutex: futex-based, 3-state (0=unlocked, 1=locked, 2=locked+waiters)
// =========================================================================

/// Mutual exclusion lock.
///
/// State encoding:
/// - 0: unlocked
/// - 1: locked, no waiters
/// - 2: locked, one or more threads waiting
#[repr(C)]
pub struct Mutex {
    state: AtomicU32,
}

impl Mutex {
    pub const fn new() -> Self {
        Mutex {
            state: AtomicU32::new(0),
        }
    }

    /// Acquire the mutex, blocking if necessary.
    ///
    /// Three-phase algorithm:
    /// 1. Fast path: uncontended CAS 0 → 1 (no syscall)
    /// 2. Spin phase: brief userspace spin before entering kernel (~40 iters)
    /// 3. Futex phase: kernel-mediated wait with swap(2) waiter flag
    ///
    /// The spin phase avoids the expensive futex_wait syscall + context switch
    /// when the lock holder is on another CPU and about to release.
    pub fn lock(&self) {
        // Fast path: uncontended CAS 0 → 1
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        note_mutex_slowpath();

        // Spin phase: try to acquire without entering the kernel.
        // On SMP, the holder may be running on another CPU and about to
        // release. A brief spin avoids the ~1µs futex syscall overhead.
        for _ in 0..40 {
            if self.state.load(Ordering::Relaxed) == 0 {
                if self
                    .state
                    .compare_exchange_weak(0, 2, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            }
            ::core::hint::spin_loop();
        }

        // Futex phase: always use swap(2) to preserve the waiter flag.
        loop {
            if self.state.swap(2, Ordering::Acquire) == 0 {
                return;
            }
            futex_wait(self.futex_ptr(), 2);
        }
    }

    /// Acquire the mutex with a timeout in nanoseconds.
    /// Returns true if the lock was acquired, false on timeout.
    pub fn lock_timeout(&self, timeout_ns: u64) -> bool {
        // Fast path: uncontended CAS 0 → 1 (no syscall)
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
        note_mutex_slowpath();

        // Slow path: always swap(2) to preserve waiter flag
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);

        loop {
            if self.state.swap(2, Ordering::Acquire) == 0 {
                return true;
            }

            let remaining_ns = remaining_timeout_ns(deadline_ns);
            if remaining_ns == 0 {
                // Timeout — last try with swap(2) to keep waiter flag correct
                return self.state.swap(2, Ordering::Acquire) == 0;
            }

            let err = futex_wait_timeout(self.futex_ptr(), 2, remaining_ns);
            if err == uapi::KERNITE_ERR_CANCELLED as u64 {
                // Timeout — last try with swap(2)
                return self.state.swap(2, Ordering::Acquire) == 0;
            }
        }
    }

    /// Try to acquire the mutex without blocking.
    /// Returns true if the lock was acquired, false otherwise.
    pub fn try_lock(&self) -> bool {
        self.state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Release the mutex.
    pub fn unlock(&self) {
        let prev = self.state.swap(0, Ordering::Release);
        if prev == 2 {
            // There were waiters — wake one
            futex_wake(self.futex_ptr(), 1);
        }
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        // SAFETY: AtomicU32 has the same layout as u32
        &self.state as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// TypedMutex: RECURSIVE and ERRORCHECK mutex types
// =========================================================================

/// Mutex type constants
pub const MUTEX_NORMAL: u8 = 0;
pub const MUTEX_RECURSIVE: u8 = 1;
pub const MUTEX_ERRORCHECK: u8 = 2;

/// Typed mutex supporting NORMAL, RECURSIVE, and ERRORCHECK semantics.
///
/// Layout is `#[repr(C)]` for C ABI compatibility. Fits in 24 bytes.
#[repr(C)]
pub struct TypedMutex {
    /// Futex word: 0=unlocked, 1=locked, 2=locked+waiters
    state: AtomicU32,
    /// Mutex type (NORMAL, RECURSIVE, ERRORCHECK)
    mutex_type: u8,
    _pad: [u8; 3],
    /// Thread ID of the current owner (u64::MAX = no owner)
    owner: ::core::sync::atomic::AtomicU64,
    /// Recursion depth (RECURSIVE only)
    count: AtomicU32,
    _pad2: [u8; 4],
}

impl TypedMutex {
    pub const fn new(mutex_type: u8) -> Self {
        TypedMutex {
            state: AtomicU32::new(0),
            mutex_type,
            _pad: [0; 3],
            owner: ::core::sync::atomic::AtomicU64::new(u64::MAX),
            count: AtomicU32::new(0),
            _pad2: [0; 4],
        }
    }

    /// Get the current thread's ID from TLS.
    #[inline]
    fn current_thread_id() -> u64 {
        if let Some(tls) = crate::thread::tls::current_tls() {
            unsafe { (*tls).thread_id }
        } else {
            0
        }
    }

    /// Lock the typed mutex.
    ///
    /// Returns `TRONA_OK` on success or a substrate status code:
    /// `TRONA_DEADLOCK` (ERRORCHECK re-entry).
    pub fn lock(&self) -> u64 {
        let tid = Self::current_thread_id();

        match self.mutex_type {
            MUTEX_RECURSIVE => {
                // If already owned by this thread, just increment count
                if self.owner.load(Ordering::Relaxed) == tid {
                    self.count.fetch_add(1, Ordering::Relaxed);
                    return TRONA_OK;
                }
                self.lock_inner();
                self.owner.store(tid, Ordering::Relaxed);
                self.count.store(1, Ordering::Relaxed);
                TRONA_OK
            }
            MUTEX_ERRORCHECK => {
                // If already owned by this thread, error out
                if self.owner.load(Ordering::Relaxed) == tid {
                    return TRONA_DEADLOCK;
                }
                self.lock_inner();
                self.owner.store(tid, Ordering::Relaxed);
                TRONA_OK
            }
            _ => {
                self.lock_inner();
                TRONA_OK
            }
        }
    }

    /// Try to lock the typed mutex without blocking.
    ///
    /// Returns `TRONA_OK` on success, `TRONA_BUSY` if the lock is held by
    /// another thread (or by this thread for ERRORCHECK).
    pub fn try_lock(&self) -> u64 {
        let tid = Self::current_thread_id();

        match self.mutex_type {
            MUTEX_RECURSIVE => {
                if self.owner.load(Ordering::Relaxed) == tid {
                    self.count.fetch_add(1, Ordering::Relaxed);
                    return TRONA_OK;
                }
                if self
                    .state
                    .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    self.owner.store(tid, Ordering::Relaxed);
                    self.count.store(1, Ordering::Relaxed);
                    TRONA_OK
                } else {
                    TRONA_BUSY
                }
            }
            MUTEX_ERRORCHECK => {
                if self.owner.load(Ordering::Relaxed) == tid {
                    return TRONA_BUSY;
                }
                if self
                    .state
                    .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    self.owner.store(tid, Ordering::Relaxed);
                    TRONA_OK
                } else {
                    TRONA_BUSY
                }
            }
            _ => {
                if self
                    .state
                    .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    TRONA_OK
                } else {
                    TRONA_BUSY
                }
            }
        }
    }

    /// Unlock the typed mutex.
    ///
    /// Returns `TRONA_OK` on success, `TRONA_INVALID_OPERATION` if the
    /// caller is not the owner (RECURSIVE/ERRORCHECK only).
    pub fn unlock(&self) -> u64 {
        match self.mutex_type {
            MUTEX_RECURSIVE => {
                let tid = Self::current_thread_id();
                if self.owner.load(Ordering::Relaxed) != tid {
                    return TRONA_INVALID_OPERATION;
                }
                let prev_count = self.count.fetch_sub(1, Ordering::Relaxed);
                if prev_count <= 1 {
                    // Final unlock
                    self.owner.store(u64::MAX, Ordering::Relaxed);
                    self.count.store(0, Ordering::Relaxed);
                    self.unlock_inner();
                }
                TRONA_OK
            }
            MUTEX_ERRORCHECK => {
                let tid = Self::current_thread_id();
                if self.owner.load(Ordering::Relaxed) != tid {
                    return TRONA_INVALID_OPERATION;
                }
                self.owner.store(u64::MAX, Ordering::Relaxed);
                self.unlock_inner();
                TRONA_OK
            }
            _ => {
                self.unlock_inner();
                TRONA_OK
            }
        }
    }

    /// Lock with timeout in nanoseconds.
    ///
    /// Returns `TRONA_OK` on success, `TRONA_TIMED_OUT` on timeout,
    /// `TRONA_DEADLOCK` on ERRORCHECK re-entry.
    pub fn lock_timeout(&self, timeout_ns: u64) -> u64 {
        let tid = Self::current_thread_id();

        match self.mutex_type {
            MUTEX_RECURSIVE => {
                if self.owner.load(Ordering::Relaxed) == tid {
                    self.count.fetch_add(1, Ordering::Relaxed);
                    return TRONA_OK;
                }
                if !self.lock_inner_timeout(timeout_ns) {
                    return TRONA_TIMED_OUT;
                }
                self.owner.store(tid, Ordering::Relaxed);
                self.count.store(1, Ordering::Relaxed);
                TRONA_OK
            }
            MUTEX_ERRORCHECK => {
                if self.owner.load(Ordering::Relaxed) == tid {
                    return TRONA_DEADLOCK;
                }
                if !self.lock_inner_timeout(timeout_ns) {
                    return TRONA_TIMED_OUT;
                }
                self.owner.store(tid, Ordering::Relaxed);
                TRONA_OK
            }
            _ => {
                if !self.lock_inner_timeout(timeout_ns) {
                    TRONA_TIMED_OUT
                } else {
                    TRONA_OK
                }
            }
        }
    }

    /// Internal: acquire the futex lock (blocking).
    fn lock_inner(&self) {
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        note_mutex_slowpath();
        // Spin phase
        for _ in 0..40 {
            if self.state.load(Ordering::Relaxed) == 0 {
                if self
                    .state
                    .compare_exchange_weak(0, 2, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            }
            ::core::hint::spin_loop();
        }
        // Futex phase
        loop {
            if self.state.swap(2, Ordering::Acquire) == 0 {
                return;
            }
            futex_wait(self.futex_ptr(), 2);
        }
    }

    /// Internal: acquire the futex lock with timeout. Returns true on success.
    fn lock_inner_timeout(&self, timeout_ns: u64) -> bool {
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
        note_mutex_slowpath();
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);
        loop {
            if self.state.swap(2, Ordering::Acquire) == 0 {
                return true;
            }

            let remaining_ns = remaining_timeout_ns(deadline_ns);
            if remaining_ns == 0 {
                return self.state.swap(2, Ordering::Acquire) == 0;
            }

            let err = futex_wait_timeout(self.futex_ptr(), 2, remaining_ns);
            if err == uapi::KERNITE_ERR_CANCELLED as u64 {
                return self.state.swap(2, Ordering::Acquire) == 0;
            }
        }
    }

    /// Internal: release the futex lock.
    fn unlock_inner(&self) {
        let prev = self.state.swap(0, Ordering::Release);
        if prev == 2 {
            futex_wake(self.futex_ptr(), 1);
        }
    }

    /// Unlock for condvar wait: fully releases the lock regardless of recursion
    /// depth, and returns the saved count for later restoration.
    ///
    /// Returns 0 if the caller is not the mutex owner (RECURSIVE/ERRORCHECK).
    /// The caller must check for 0 and skip the wait if ownership verification fails.
    pub(crate) fn condvar_unlock(&self) -> u32 {
        match self.mutex_type {
            MUTEX_RECURSIVE => {
                let tid = Self::current_thread_id();
                if self.owner.load(Ordering::Relaxed) != tid {
                    return 0; // Caller is not the owner
                }
                let saved = self.count.swap(0, Ordering::Relaxed);
                self.owner.store(u64::MAX, Ordering::Relaxed);
                self.unlock_inner();
                saved
            }
            MUTEX_ERRORCHECK => {
                let tid = Self::current_thread_id();
                if self.owner.load(Ordering::Relaxed) != tid {
                    return 0; // Caller is not the owner
                }
                self.owner.store(u64::MAX, Ordering::Relaxed);
                self.unlock_inner();
                1
            }
            _ => {
                self.unlock_inner();
                1
            }
        }
    }

    /// Re-lock after condvar wait: reacquires the lock and restores owner/count.
    pub(crate) fn condvar_relock(&self, saved_count: u32) {
        self.lock_inner();
        let tid = Self::current_thread_id();
        self.owner.store(tid, Ordering::Relaxed);
        if self.mutex_type == MUTEX_RECURSIVE {
            self.count.store(saved_count, Ordering::Relaxed);
        }
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        &self.state as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Condvar: futex-based, sequence counter
// =========================================================================

/// Condition variable.
///
/// Uses a sequence counter that increments on signal/broadcast. Waiters
/// record the current sequence, release the mutex, then futex_wait on the
/// counter. This avoids lost wakeups.
#[repr(C)]
pub struct Condvar {
    seq: AtomicU32,
}

impl Condvar {
    pub const fn new() -> Self {
        Condvar {
            seq: AtomicU32::new(0),
        }
    }

    /// Wait on the condition variable, releasing `mutex` atomically.
    ///
    /// The caller must hold `mutex`. It is released before blocking and
    /// re-acquired before returning. This is a cancellation point.
    pub fn wait(&self, mutex: &Mutex) {
        let current_seq = self.seq.load(Ordering::Relaxed);
        mutex.unlock();
        set_blocked_futex(self.futex_ptr());
        futex_wait(self.futex_ptr(), current_seq);
        clear_blocked_futex();
        mutex.lock();
        // Cancellation point: check after re-acquiring mutex
        check_cancellation();
    }

    /// Wait on the condition variable with a timeout in nanoseconds.
    ///
    /// Returns `TRONA_OK` on successful wake, `TRONA_TIMED_OUT` on timeout.
    /// This is a cancellation point.
    pub fn wait_timeout(&self, mutex: &Mutex, timeout_ns: u64) -> u64 {
        let current_seq = self.seq.load(Ordering::Relaxed);
        mutex.unlock();
        set_blocked_futex(self.futex_ptr());
        let err = futex_wait_timeout(self.futex_ptr(), current_seq, timeout_ns);
        clear_blocked_futex();
        mutex.lock();
        // Cancellation point: check after re-acquiring mutex
        check_cancellation();
        if err == uapi::KERNITE_ERR_CANCELLED as u64 {
            TRONA_TIMED_OUT
        } else {
            TRONA_OK
        }
    }

    /// Wait on the condition variable with a typed mutex (RECURSIVE/ERRORCHECK).
    ///
    /// Fully releases the mutex (saving recursion count), blocks, then
    /// re-acquires with the original count restored. This is a cancellation point.
    ///
    /// Returns `TRONA_OK` on successful wake, `TRONA_INVALID_OPERATION`
    /// if the caller does not own the mutex.
    pub fn wait_typed(&self, mutex: &TypedMutex) -> u64 {
        let current_seq = self.seq.load(Ordering::Relaxed);
        let saved = mutex.condvar_unlock();
        if saved == 0 {
            return TRONA_INVALID_OPERATION;
        }
        set_blocked_futex(self.futex_ptr());
        futex_wait(self.futex_ptr(), current_seq);
        clear_blocked_futex();
        mutex.condvar_relock(saved);
        check_cancellation();
        TRONA_OK
    }

    /// Wait on the condition variable with a typed mutex and timeout.
    ///
    /// Returns `TRONA_OK` on successful wake, `TRONA_TIMED_OUT` on timeout,
    /// `TRONA_INVALID_OPERATION` if the caller does not own the mutex.
    /// This is a cancellation point.
    pub fn wait_timeout_typed(&self, mutex: &TypedMutex, timeout_ns: u64) -> u64 {
        let current_seq = self.seq.load(Ordering::Relaxed);
        let saved = mutex.condvar_unlock();
        if saved == 0 {
            return TRONA_INVALID_OPERATION;
        }
        set_blocked_futex(self.futex_ptr());
        let err = futex_wait_timeout(self.futex_ptr(), current_seq, timeout_ns);
        clear_blocked_futex();
        mutex.condvar_relock(saved);
        check_cancellation();
        if err == uapi::KERNITE_ERR_CANCELLED as u64 {
            TRONA_TIMED_OUT
        } else {
            TRONA_OK
        }
    }

    /// Wake one waiting thread.
    pub fn signal(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        futex_wake(self.futex_ptr(), 1);
    }

    /// Wake all waiting threads.
    pub fn broadcast(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        futex_wake(self.futex_ptr(), u32::MAX);
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        &self.seq as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// RWLock: futex-based, reader count + writer bit
// =========================================================================

/// Reader-writer lock.
///
/// State encoding (in a single u32):
/// - bits 30:0 = reader count (0..2^31-1)
/// - bit 31 = writer lock held
/// - A separate waiter word is used for writer wake ordering.
#[repr(C)]
pub struct RWLock {
    state: AtomicU32,
    writer_wake: AtomicU32,
    writer_waiting: AtomicU32,
}

const WRITER_BIT: u32 = 1 << 31;

impl RWLock {
    pub const fn new() -> Self {
        RWLock {
            state: AtomicU32::new(0),
            writer_wake: AtomicU32::new(0),
            writer_waiting: AtomicU32::new(0),
        }
    }

    /// Acquire a shared (read) lock.
    ///
    /// Yields to waiting writers: if a writer is queued, new readers wait
    /// rather than acquiring immediately, preventing writer starvation.
    pub fn read_lock(&self) {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & WRITER_BIT == 0 && self.writer_waiting.load(Ordering::Relaxed) == 0 {
                // No writer holding or waiting — try to increment reader count
                if self
                    .state
                    .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            } else {
                // Writer holds lock or is waiting — wait for writer_wake
                futex_wait(
                    self.writer_futex_ptr(),
                    self.writer_wake.load(Ordering::Relaxed),
                );
            }
        }
    }

    /// Release a shared (read) lock.
    pub fn read_unlock(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        if prev == 1 {
            // Last reader — wake a waiting writer
            self.writer_wake.fetch_add(1, Ordering::Release);
            futex_wake(self.writer_futex_ptr(), 1);
        }
    }

    /// Acquire an exclusive (write) lock.
    pub fn write_lock(&self) {
        // Fast path: no contention
        if self
            .state
            .compare_exchange_weak(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        // Signal that a writer is waiting so new readers yield
        self.writer_waiting.fetch_add(1, Ordering::Relaxed);
        loop {
            if self
                .state
                .compare_exchange_weak(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.writer_waiting.fetch_sub(1, Ordering::Relaxed);
                return;
            }
            let s = self.state.load(Ordering::Relaxed);
            if s != 0 {
                futex_wait(
                    self.writer_futex_ptr(),
                    self.writer_wake.load(Ordering::Relaxed),
                );
            }
        }
    }

    /// Release an exclusive (write) lock.
    pub fn write_unlock(&self) {
        self.state.fetch_and(!WRITER_BIT, Ordering::Release);
        // Wake all — both readers and writers
        self.writer_wake.fetch_add(1, Ordering::Release);
        futex_wake(self.writer_futex_ptr(), u32::MAX);
    }

    /// Try to acquire a shared (read) lock without blocking.
    /// Returns true if acquired, false if a writer holds the lock.
    pub fn try_read_lock(&self) -> bool {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & WRITER_BIT != 0 {
                return false;
            }
            if self
                .state
                .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Try to acquire an exclusive (write) lock without blocking.
    /// Returns true if acquired, false if any readers or writer hold the lock.
    pub fn try_write_lock(&self) -> bool {
        self.state
            .compare_exchange(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Acquire a shared (read) lock with a timeout in nanoseconds.
    /// Returns true if acquired, false on timeout.
    pub fn read_lock_timeout(&self, timeout_ns: u64) -> bool {
        // Fast path: try uncontended read lock before computing deadline
        let s = self.state.load(Ordering::Relaxed);
        if s & WRITER_BIT == 0 && self.writer_waiting.load(Ordering::Relaxed) == 0 {
            if self
                .state
                .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & WRITER_BIT == 0 && self.writer_waiting.load(Ordering::Relaxed) == 0 {
                if self
                    .state
                    .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return true;
                }
                continue;
            }
            let remaining = remaining_timeout_ns(deadline_ns);
            if remaining == 0 {
                return false;
            }
            let wake_val = self.writer_wake.load(Ordering::Relaxed);
            let err = futex_wait_timeout(self.writer_futex_ptr(), wake_val, remaining);
            if err == uapi::KERNITE_ERR_CANCELLED as u64 {
                // Timeout — one last try
                let s2 = self.state.load(Ordering::Relaxed);
                if s2 & WRITER_BIT == 0 {
                    if self
                        .state
                        .compare_exchange(s2, s2 + 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                    {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    /// Acquire an exclusive (write) lock with a timeout in nanoseconds.
    /// Returns true if acquired, false on timeout.
    pub fn write_lock_timeout(&self, timeout_ns: u64) -> bool {
        // Fast path
        if self
            .state
            .compare_exchange_weak(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
        self.writer_waiting.fetch_add(1, Ordering::Relaxed);
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);
        loop {
            if self
                .state
                .compare_exchange_weak(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.writer_waiting.fetch_sub(1, Ordering::Relaxed);
                return true;
            }
            let s = self.state.load(Ordering::Relaxed);
            if s != 0 {
                let remaining = remaining_timeout_ns(deadline_ns);
                if remaining == 0 {
                    self.writer_waiting.fetch_sub(1, Ordering::Relaxed);
                    return false;
                }
                let wake_val = self.writer_wake.load(Ordering::Relaxed);
                let err = futex_wait_timeout(self.writer_futex_ptr(), wake_val, remaining);
                if err == uapi::KERNITE_ERR_CANCELLED as u64 {
                    // Timeout — one last try
                    if self
                        .state
                        .compare_exchange(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                    {
                        self.writer_waiting.fetch_sub(1, Ordering::Relaxed);
                        return true;
                    }
                    self.writer_waiting.fetch_sub(1, Ordering::Relaxed);
                    return false;
                }
            }
        }
    }

    #[inline]
    fn writer_futex_ptr(&self) -> *const u32 {
        &self.writer_wake as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Barrier: count-down + futex broadcast
// =========================================================================

/// Thread barrier: blocks threads until `count` threads have arrived.
#[repr(C)]
pub struct Barrier {
    count: u32,
    waiting: AtomicU32,
    phase: AtomicU32,
}

impl Barrier {
    pub const fn new(count: u32) -> Self {
        Barrier {
            count,
            waiting: AtomicU32::new(0),
            phase: AtomicU32::new(0),
        }
    }

    /// Wait at the barrier. Returns true for exactly one thread (the "leader"
    /// that triggers the release), false for all others.
    pub fn wait(&self) -> bool {
        let phase = self.phase.load(Ordering::Relaxed);
        let prev = self.waiting.fetch_add(1, Ordering::AcqRel);

        if prev + 1 == self.count {
            // Last thread to arrive — reset counter and advance phase
            self.waiting.store(0, Ordering::Release);
            self.phase.fetch_add(1, Ordering::Release);
            futex_wake(self.phase_futex_ptr(), u32::MAX);
            true
        } else {
            // Wait for phase to change
            loop {
                futex_wait(self.phase_futex_ptr(), phase);
                if self.phase.load(Ordering::Acquire) != phase {
                    break;
                }
            }
            false
        }
    }

    #[inline]
    fn phase_futex_ptr(&self) -> *const u32 {
        &self.phase as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Semaphore: futex-based counting semaphore
// =========================================================================

/// Maximum value for a counting semaphore.
pub const SEM_VALUE_MAX: u32 = i32::MAX as u32;

/// Counting semaphore.
///
/// The count itself is the futex word: waiters call `futex_wait(ptr, 0)` when
/// the count is zero, and `post` wakes one waiter when count transitions
/// from 0 to 1.
#[repr(C)]
pub struct Semaphore {
    count: AtomicU32,
}

impl Semaphore {
    pub const fn new(initial: u32) -> Self {
        Semaphore {
            count: AtomicU32::new(initial),
        }
    }

    /// Re-initialize the semaphore. Returns 0 on success, -1 if value exceeds
    /// SEM_VALUE_MAX.
    pub fn init(&self, value: u32) -> i32 {
        if value > SEM_VALUE_MAX {
            return -1;
        }
        self.count.store(value, Ordering::Release);
        if value > 0 {
            futex_wake(self.futex_ptr(), u32::MAX);
        }
        0
    }

    /// Decrement (wait). Blocks if the count is zero.
    pub fn wait(&self) {
        loop {
            let c = self.count.load(Ordering::Relaxed);
            if c > 0 {
                if self
                    .count
                    .compare_exchange_weak(c, c - 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            } else {
                futex_wait(self.futex_ptr(), 0);
            }
        }
    }

    /// Try to decrement without blocking.
    /// Returns true if decremented, false if count was zero.
    pub fn try_wait(&self) -> bool {
        loop {
            let c = self.count.load(Ordering::Relaxed);
            if c == 0 {
                return false;
            }
            if self
                .count
                .compare_exchange_weak(c, c - 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Decrement with timeout in nanoseconds.
    /// Returns `TRONA_OK` on success, `TRONA_TIMED_OUT` on timeout.
    pub fn wait_timeout(&self, timeout_ns: u64) -> u64 {
        // Fast path: uncontended decrement before computing deadline
        let c = self.count.load(Ordering::Relaxed);
        if c > 0 {
            if self
                .count
                .compare_exchange_weak(c, c - 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return TRONA_OK;
            }
        }
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);
        loop {
            let c = self.count.load(Ordering::Relaxed);
            if c > 0 {
                if self
                    .count
                    .compare_exchange_weak(c, c - 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return TRONA_OK;
                }
                continue;
            }
            let remaining = remaining_timeout_ns(deadline_ns);
            if remaining == 0 {
                // Last-chance try
                let c2 = self.count.load(Ordering::Relaxed);
                if c2 > 0 {
                    if self
                        .count
                        .compare_exchange(c2, c2 - 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                    {
                        return TRONA_OK;
                    }
                }
                return TRONA_TIMED_OUT;
            }
            let err = futex_wait_timeout(self.futex_ptr(), 0, remaining);
            if err == uapi::KERNITE_ERR_CANCELLED as u64 {
                // Last-chance try
                let c2 = self.count.load(Ordering::Relaxed);
                if c2 > 0 {
                    if self
                        .count
                        .compare_exchange(c2, c2 - 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                    {
                        return TRONA_OK;
                    }
                }
                return TRONA_TIMED_OUT;
            }
        }
    }

    /// Increment (post). Returns 0 on success, -1 on overflow.
    pub fn post(&self) -> i32 {
        loop {
            let c = self.count.load(Ordering::Relaxed);
            if c >= SEM_VALUE_MAX {
                return -1;
            }
            if self
                .count
                .compare_exchange_weak(c, c + 1, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                if c == 0 {
                    // Was zero, wake one waiter
                    futex_wake(self.futex_ptr(), 1);
                }
                return 0;
            }
        }
    }

    /// Get the current value.
    pub fn get_value(&self) -> i32 {
        self.count.load(Ordering::Relaxed) as i32
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        &self.count as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Once: run-exactly-once initialization
// =========================================================================

/// States for `Once`
const ONCE_UNINIT: u32 = 0;
const ONCE_RUNNING: u32 = 1;
const ONCE_COMPLETE: u32 = 2;

/// Execute a closure exactly once, even across multiple threads.
#[repr(C)]
pub struct Once {
    state: AtomicU32,
}

impl Once {
    pub const fn new() -> Self {
        Once {
            state: AtomicU32::new(ONCE_UNINIT),
        }
    }

    /// Execute `f` if this is the first call. All subsequent calls are no-ops.
    /// Concurrent callers block until the first caller's `f` returns.
    pub fn call_once(&self, f: unsafe extern "C" fn()) {
        match self.state.load(Ordering::Acquire) {
            ONCE_COMPLETE => return,
            ONCE_UNINIT => {
                if self
                    .state
                    .compare_exchange(
                        ONCE_UNINIT,
                        ONCE_RUNNING,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    unsafe { f() };
                    self.state.store(ONCE_COMPLETE, Ordering::Release);
                    futex_wake(self.futex_ptr(), u32::MAX);
                    return;
                }
            }
            _ => {}
        }

        // Wait for ONCE_COMPLETE
        loop {
            let s = self.state.load(Ordering::Acquire);
            if s == ONCE_COMPLETE {
                return;
            }
            futex_wait(self.futex_ptr(), ONCE_RUNNING);
        }
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        &self.state as *const AtomicU32 as *const u32
    }
}
