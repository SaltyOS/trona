//! Self-wake timer helper for IPC server loops.
//!
//! Timed IPC syscalls are retired, so services that need
//! "wake me after N ns unless a real request arrives first"
//! can spawn a tiny helper thread that sleeps on a condvar and
//! injects a synthetic message through the service's client-facing
//! endpoint when the current deadline expires.
//!
//! The helper is intentionally simple:
//! - one timer thread per service loop
//! - one outstanding deadline at a time
//! - stale wake messages are filtered by a sequence number
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::core::slot_pool::SlotPool;
use crate::thread::sync::{Condvar, Mutex};
use crate::thread::{self, SpawnError};
use trona_kernel::core_types::{Cap, CapRef, TronaMsg};
use trona_kernel::ipc;

const IPC_LABEL_MASK: u64 = 0xFF_FFFF_FFFF;

#[repr(C)]
pub struct IpcTimer {
    mutex: Mutex,
    cv: Condvar,
    deadline_ns: AtomicU64,
    seq: AtomicU64,
    wake_ep: AtomicU64,
    started: AtomicBool,
    label: u64,
}

impl IpcTimer {
    pub const fn new(label: u64) -> Self {
        Self {
            mutex: Mutex::new(),
            cv: Condvar::new(),
            deadline_ns: AtomicU64::new(0),
            seq: AtomicU64::new(1),
            wake_ep: AtomicU64::new(0),
            started: AtomicBool::new(false),
            label: label & IPC_LABEL_MASK,
        }
    }

    pub unsafe fn start_with_runtime_untyped(&self, wake_ep: Cap) -> Result<(), SpawnError> {
        let cfg = thread::SpawnConfig::for_runtime_bootstrap_untyped()?;
        unsafe { self.start_with_config(wake_ep, &cfg) }
    }

    pub unsafe fn start_with_runtime_thread(&self, wake_ep: Cap) -> Result<(), SpawnError> {
        let cfg = thread::SpawnConfig::for_runtime_thread();
        unsafe { self.start_with_config(wake_ep, &cfg) }
    }

    pub unsafe fn start_with_untyped(&self, wake_ep: Cap, untyped: Cap) -> Result<(), SpawnError> {
        let cfg = thread::SpawnConfig::new(CapRef::flat(untyped));
        unsafe { self.start_with_config(wake_ep, &cfg) }
    }

    /// Start the timer thread drawing its TCB / SC / IPC / stack /
    /// TLS slots from a private `SlotPool` instead of the process-wide
    /// `slot_alloc`. Use this when the timer must coexist with a
    /// worker pool whose partial spawn could otherwise exhaust the
    /// shared global allocator.
    pub unsafe fn start_with_pool(
        &self,
        wake_ep: Cap,
        untyped: Cap,
        pool: &'static SlotPool,
    ) -> Result<(), SpawnError> {
        let cfg = thread::SpawnConfig::new(CapRef::flat(untyped)).with_slot_pool(pool);
        unsafe { self.start_with_config(wake_ep, &cfg) }
    }

    unsafe fn start_with_config(
        &self,
        wake_ep: Cap,
        cfg: &thread::SpawnConfig,
    ) -> Result<(), SpawnError> {
        if self.started.load(Ordering::Acquire) {
            self.wake_ep.store(wake_ep, Ordering::Release);
            return Ok(());
        }

        self.wake_ep.store(wake_ep, Ordering::Release);
        unsafe {
            thread::spawn_fn(timer_thread_entry, self as *const Self as *mut u8, cfg)?;
        }
        self.started.store(true, Ordering::Release);
        Ok(())
    }

    pub fn arm_after(&self, timeout_ns: u64) -> u64 {
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);
        self.arm_at(deadline_ns)
    }

    pub fn arm_at(&self, deadline_ns: u64) -> u64 {
        self.mutex.lock();
        let seq = self.seq.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        self.deadline_ns.store(deadline_ns, Ordering::Release);
        self.cv.signal();
        self.mutex.unlock();
        seq
    }

    pub fn disarm(&self) -> u64 {
        self.mutex.lock();
        let seq = self.seq.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        self.deadline_ns.store(0, Ordering::Release);
        self.cv.signal();
        self.mutex.unlock();
        seq
    }

    #[inline]
    pub fn is_timeout_message(&self, msg: &TronaMsg) -> bool {
        msg.label == self.label
            && msg.length > 0
            && msg.regs[0] == self.seq.load(Ordering::Acquire)
            && self.deadline_ns.load(Ordering::Acquire) == 0
    }

    #[inline]
    pub fn is_armed_timeout_message(&self, msg: &TronaMsg, armed_seq: u64) -> bool {
        msg.label == self.label
            && msg.length > 0
            && msg.regs[0] == armed_seq
            && self.deadline_ns.load(Ordering::Acquire) == 0
    }

    /// The (mask-truncated) wire label this timer stamps on its wake messages.
    /// A server can recognise a *stale* timer record — one fired for a previous
    /// arm whose sequence no longer matches — by label and swallow it as a
    /// progress wake instead of dispatching it as a bogus client request.
    #[inline]
    pub fn label(&self) -> u64 {
        self.label
    }
}

fn monotonic_now_ns() -> u64 {
    trona_kernel::syscall::clock_read_monotonic(crate::client::caps::clock_cap().addr())
}

unsafe extern "C" fn timer_thread_entry(arg: *mut u8) {
    let timer = unsafe { &*(arg as *const IpcTimer) };

    loop {
        timer.mutex.lock();
        loop {
            let deadline_ns = timer.deadline_ns.load(Ordering::Acquire);
            if deadline_ns == 0 {
                timer.cv.wait(&timer.mutex);
                continue;
            }

            let now_ns = monotonic_now_ns();
            if deadline_ns > now_ns {
                let _ = timer.cv.wait_timeout(&timer.mutex, deadline_ns - now_ns);
                continue;
            }

            let seq = timer.seq.load(Ordering::Acquire);
            let wake_ep = timer.wake_ep.load(Ordering::Acquire);
            timer.deadline_ns.store(0, Ordering::Release);
            timer.mutex.unlock();

            if wake_ep != 0 {
                let mut msg = TronaMsg::zeroed();
                msg.label = timer.label;
                msg.length = 1;
                msg.regs[0] = seq;
                let _ =
                    unsafe { ipc::mp_write_ctx(crate::current_ipc_ctx(), wake_ep, &raw const msg) };
            } else {
                trona_kernel::syscall::yield_now();
            }
            break;
        }
    }
}
