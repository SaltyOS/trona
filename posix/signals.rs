// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX signal handling.
//!
//! Signal delivery rides on the `MessagePipe` + `Watch` +
//! `EventQueue` triple:
//!
//! ```text
//!   init  ──MP_WRITE(signum)──▶  signal_pipe ──STATE_READABLE──▶ Watch ─▶ wakeup_eq
//!                                                                            │
//!                                                                            ▼
//!                                       posix wrapper / sleep loop drains via EQ
//! ```
//!
//! - **Producer (init server)**: each process has a single
//!   per-process signal `MessagePipe` whose producer side init holds.
//!   `kill(pid, sig)` writes a one-record message
//!   (`regs[0] = signum`) into the pipe.
//!
//! - **Routing (per-thread Watch)**: `posix::wakeup` lazily retypes
//!   a `Watch` armed against `signal_pipe`'s `KERNITE_STATE_READABLE`
//!   bit. Each transition enqueues a `STATE` record into the
//!   thread's wakeup `EventQueue`, tagged
//!   `wakeup::WAKEUP_COOKIE_SIGNAL_PIPE`.
//!
//! - **Consumer (this module)**: `posix_sigcheck` polls the wakeup
//!   EQ non-blocking; sleep paths block on `wakeup::wait_record()`
//!   and dispatch any signal records they observe before resuming.
//!   Pending signal bits accumulate in
//!   `__sig_pending_bits: AtomicU64` and are dispatched after each
//!   atomic swap.

use crate::types::*;
use crate::wakeup;
use crate::*;
use core::sync::atomic::Ordering;
use trona_kernel::core_types::*;
use trona_protocol::posix::*;

/// Returns `true` if the default action for `sig` is to terminate
/// the process.
fn sig_default_action(sig: i32) -> bool {
    match sig {
        SIGCHLD | SIGCONT | SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => false,
        _ => true,
    }
}

/// One-shot initialization that publishes the disposition tables to
/// init. The actual signal-delivery channel (signal pipe → Watch →
/// wakeup EQ) is materialised on demand by `wakeup`.
unsafe fn sig_init() {
    let _ = crate::__sig_initialized.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
}

/// Reinstall per-process signal state in a fork child. The child
/// inherits handler tables but gets a fresh wakeup EQ + signal pipe
/// from its spawner; everything is re-materialised on first use.
pub(crate) unsafe fn sig_reinit_after_fork() {
    if crate::__sig_initialized.load(Ordering::SeqCst) == 0 {
        return;
    }
    crate::__sig_initialized.store(0, Ordering::SeqCst);
    unsafe {
        *(&raw mut crate::__sig_last_restart) = false;
    }
    crate::__sig_pending_bits.store(0, Ordering::SeqCst);
}

/// Install a signal handler for signal `sig`.
///
/// `handler` is one of: `SIG_DFL` (default), `SIG_IGN` (ignore), or a
/// function pointer cast to `usize`. Returns the previous handler, or
/// `SIG_ERR` (`usize::MAX`) on error. Notifies init of the new
/// disposition category so the supervisor can decide whether to
/// deliver or suppress signals.
pub unsafe fn posix_signal(sig: i32, handler: usize) -> usize {
    unsafe {
        sig_init();

        if sig <= 0 || sig >= NSIG as i32 || sig == SIGKILL || sig == SIGSTOP {
            return usize::MAX; // SIG_ERR
        }
        if handler == usize::MAX {
            return usize::MAX; // SIG_ERR
        }

        let old = crate::__sig_handlers[sig as usize].load(Ordering::SeqCst);
        crate::__sig_handlers[sig as usize].store(handler, Ordering::SeqCst);

        let disp: u64 = if handler == SIG_DFL {
            SIG_DISP_DFL
        } else if handler == SIG_IGN {
            SIG_DISP_IGN
        } else {
            SIG_DISP_CATCH
        };

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_SIGACTION;
        msg.length = 3;
        msg.regs[0] = sig as u64;
        msg.regs[1] = disp;
        msg.regs[2] = 1;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
            crate::__sig_handlers[sig as usize].store(old, Ordering::SeqCst);
            return usize::MAX; // SIG_ERR
        }

        old
    }
}

unsafe fn fold_supervisor_pending() {
    unsafe {
        let ctx = crate::tls::current_ipc_ctx();
        if ctx.is_null() {
            return;
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_SIGPENDING_DUMP;
        msg.length = 0;

        let err = trona_kernel::ipc::mp_call_ctx(
            ctx,
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );

        if err == 0 && reply.label == (uapi::KERNITE_OK as u64) {
            let pending = reply.regs[0];
            if pending != 0 {
                crate::__sig_pending_bits.fetch_or(pending, Ordering::AcqRel);
            }
        }
    }
}

/// Run signal handlers for any pending, unblocked signals.
///
/// Drains the wakeup EQ non-blocking — any signal-pipe-readable
/// records there cause `wakeup::drain_signal_pipe()` to fold the
/// pipe's contents into `__sig_pending_bits`. init also keeps a
/// coalesced pending mask for semantic signals whose pipe wake nudge
/// could not be queued; this function folds that mask in with a
/// bounded init call before dispatching.
///
/// Returns the number of signals dispatched. Updates
/// `__sig_last_restart`: `true` iff every dispatched signal had
/// `SA_RESTART` set — POSIX wrappers test this to decide whether to
/// retry after EINTR.
pub unsafe fn posix_sigcheck() -> i32 {
    unsafe {
        sig_init();
        fold_supervisor_pending();

        // Drain every pending wakeup-EQ record. Timer records (from
        // sleep arming) are ignored here; signal-pipe records cause
        // `drain_signal_pipe` to populate `__sig_pending_bits`.
        loop {
            match wakeup::poll_record() {
                Some(rec) => {
                    if rec.cookie == wakeup::WAKEUP_COOKIE_SIGNAL_PIPE {
                        wakeup::drain_signal_pipe();
                    }
                }
                None => break,
            }
        }

        let pending = crate::__sig_pending_bits.swap(0, Ordering::AcqRel);
        if pending == 0 {
            *(&raw mut crate::__sig_last_restart) = false;
            return 0;
        }
        dispatch_pending_bits(pending)
    }
}

/// Dispatch handlers for every signal whose bit is set in `bits`.
/// Blocked signals are OR-ed back into `__sig_pending_bits` so they
/// fire on the next `sigprocmask` unblock or `sigcheck` cycle.
unsafe fn dispatch_pending_bits(bits: u64) -> i32 {
    unsafe {
        let blocked = *(&raw const crate::__sig_blocked_mask);
        let mut repost: u64 = 0;
        let mut dispatched: i32 = 0;
        let mut any_no_restart = false;

        for sig in 1..NSIG as i32 {
            if bits & (1u64 << sig) == 0 {
                continue;
            }
            if blocked & (1u32 << sig) != 0 {
                repost |= 1u64 << sig;
                continue;
            }

            let handler = crate::__sig_handlers[sig as usize].load(Ordering::SeqCst);
            if handler == SIG_IGN {
                // explicitly ignored; consume the bit
            } else if handler == SIG_DFL {
                if sig_default_action(sig) {
                    crate::proc::posix_exit(128 + sig);
                }
            } else {
                let saved_mask = *(&raw const crate::__sig_blocked_mask);
                let sa_mask = (*(&raw const crate::__sig_sa_mask))[sig as usize];
                (*(&raw mut crate::__sig_blocked_mask)) = saved_mask | sa_mask | (1u32 << sig);

                let sa_flags = (*(&raw const crate::__sig_sa_flags))[sig as usize];
                if sa_flags & SA_RESETHAND != 0 {
                    crate::__sig_handlers[sig as usize].store(SIG_DFL, Ordering::SeqCst);
                    let mut msg = TronaMsg::zeroed();
                    let mut reply = TronaMsg::zeroed();
                    msg.label = INIT_SIGACTION;
                    msg.length = 3;
                    msg.regs[0] = sig as u64;
                    msg.regs[1] = SIG_DISP_DFL;
                    msg.regs[2] = 1;
                    let _ = trona_kernel::ipc::mp_call_ctx(
                        crate::tls::current_ipc_ctx(),
                        trona_runtime::client::caps::init_ep().addr(),
                        &raw const msg,
                        &raw mut reply,
                        trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
                    );
                }

                if sa_flags & SA_RESTART == 0 {
                    any_no_restart = true;
                }

                let func: unsafe extern "C" fn(i32) = ::core::mem::transmute(handler);
                func(sig);

                (*(&raw mut crate::__sig_blocked_mask)) = saved_mask;
            }
            dispatched += 1;
        }

        if repost != 0 {
            crate::__sig_pending_bits.fetch_or(repost, Ordering::AcqRel);
        }

        *(&raw mut crate::__sig_last_restart) = dispatched > 0 && !any_no_restart;
        dispatched
    }
}
