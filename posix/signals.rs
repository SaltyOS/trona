//! POSIX signal handling via notification-based delivery
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Two delivery mechanisms:
//!
//! 1. **Cooperative polling** (`posix_sigcheck`): userspace explicitly polls
//!    `CAP_SIGNAL_NTFN` for pending signal bits and dispatches handlers.
//!
//! 2. **Kernel-injected notification frame** (`__signal_dispatcher`): when a
//!    blocking IPC Call is interrupted by a bound notification, the kernel
//!    pushes a `NotifFrame` onto the user stack and redirects execution here.
//!    After handlers run, `SYS_NOTIF_RETURN` restores the original context
//!    and the interrupted syscall returns EINTR.
//!
//! Signal disposition is tracked both locally (handler function pointers in
//! `__sig_handlers`) and in the process manager (SIG_DFL/SIG_IGN/SIG_CATCH).
//! Blocked signals are re-raised so they remain pending.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::protocol::*;
use trona::types::core::*;
use trona::types::posix::*;
use ::core::sync::atomic::Ordering;

// Standard child CSpace layout
const CAP_PROCMGR_EP: u64 = 3;
const CAP_SIGNAL_NTFN: u64 = 6;

/// Magic value matching the kernel's `NOTIFFRAME_MAGIC`.
const NOTIFFRAME_MAGIC: u64 = 0x5A17_5349_4746_524D;

/// Signal frame injected by the kernel onto the user stack.
/// Layout must match the kernel's `NotifFrame` exactly.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(64))]
pub struct SigFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub notification_bits: u64,
    pub interrupted_syscall: u64,
    pub syscall_cap_ptr: u64,
    pub syscall_msg_info: u64,
    pub restart_syscall: u64,
    pub magic: u64,
    pub fpu_saved: u64,
    pub _fpu_pad: [u64; 7],
    pub fpu_state: [u8; 832],
}

/// Signal frame (aarch64 variant).
#[cfg(target_arch = "aarch64")]
#[repr(C, align(16))]
pub struct SigFrame {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub notification_bits: u64,
    pub interrupted_syscall: u64,
    pub syscall_cap_ptr: u64,
    pub syscall_msg_info: u64,
    pub restart_syscall: u64,
    pub magic: u64,
    pub fpu_saved: u64,
    pub _fpu_pad: [u64; 1],
    pub fpu_state: [u8; 528],
}

/// Returns `true` if the default action for `sig` is to terminate the process.
fn sig_default_action(sig: i32) -> bool {
    // Returns true if default action is terminate
    match sig {
        SIGCHLD | SIGCONT | SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => false,
        _ => true,
    }
}

/// One-shot initialization of signal state (idempotent via compare_exchange).
/// Binds the signal notification to this thread's TCB and registers the
/// kernel signal dispatcher. Both are needed for EINTR support:
/// - Bind: allows the kernel to wake us from blocking IPC when signaled
/// - Dispatcher: tells the kernel WHERE to redirect execution on wake
unsafe fn sig_init() {
    if crate::__sig_initialized
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        // Bind signal notification to our TCB (enables kernel wakeup on signal)
        trona::invoke::tcb_bind_notification(CAP_SELF_TCB, CAP_SIGNAL_NTFN);
        // Register signal dispatcher (enables signal frame injection)
        trona::invoke::tcb_set_notification_dispatcher(
            CAP_SELF_TCB,
            __signal_dispatcher as *const () as usize as u64,
        );
    }
}

/// Reinstall per-TCB signal delivery state in a fork child.
///
/// The child inherits the process-global POSIX signal tables, but it runs on a
/// fresh TCB with a fresh signal notification cap. Re-run the one-time signal
/// init against the child's TCB so kernel notification delivery and userspace
/// signal state stay consistent after fork.
pub(crate) unsafe fn sig_reinit_after_fork() {
    if crate::__sig_initialized.load(Ordering::SeqCst) == 0 {
        return;
    }

    crate::__sig_initialized.store(0, Ordering::SeqCst);
    sig_init();
    *(&raw mut crate::__sig_last_restart) = false;
}

/// Install a signal handler for signal `sig`.
///
/// `handler` is one of: `SIG_DFL` (default), `SIG_IGN` (ignore), or a
/// function pointer cast to `usize`. Returns the previous handler, or
/// `SIG_ERR` (usize::MAX) on error.
///
/// Notifies the process manager of the new disposition category so it
/// can decide whether to deliver or suppress signals.
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

        // Notify procmgr of disposition category
        let disp: u64 = if handler == SIG_DFL {
            SIG_DISP_DFL
        } else if handler == SIG_IGN {
            SIG_DISP_IGN
        } else {
            SIG_DISP_CATCH
        };

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_SIGACTION;
        msg.length = 2;
        msg.regs[0] = sig as u64;
        msg.regs[1] = disp;

        let err = crate::ipc_call_retry(CAP_PROCMGR_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            // Revert on failure
            crate::__sig_handlers[sig as usize].store(old, Ordering::SeqCst);
            return usize::MAX; // SIG_ERR
        }

        old
    }
}

/// Poll for pending signals and dispatch handlers.
///
/// Polls `CAP_SIGNAL_NTFN` for signal bits. For each pending signal:
/// - If blocked: re-raises it via `SYS_SIGNAL` so it stays pending.
/// - If SIG_IGN: silently consumed.
/// - If SIG_DFL with terminate action: calls `posix_exit(128 + sig)`.
/// - Otherwise: saves/restores the blocked mask, handles SA_RESETHAND,
///   and calls the user handler function.
///
/// SA_RESTART is handled at the POSIX wrapper level (e.g., `posix_read`),
/// not here. When a blocking IPC is interrupted, the kernel delivers
/// the signal via `__signal_dispatcher` (notif_return trampoline) and the
/// syscall returns EINTR. POSIX wrappers check SA_RESTART and retry.
///
/// Returns the number of signals dispatched (0 if none pending).
pub unsafe fn posix_sigcheck() -> i32 {
    unsafe {
        sig_init();

        let mut bits: u64 = 0;
        let r = trona::syscall::syscall(SYS_POLL, CAP_SIGNAL_NTFN, 0, 0, 0, 0, 0);
        let err = r.error as i32;
        if err == 0 {
            bits = r.value;
        }
        if err != 0 || bits == 0 {
            return 0;
        }

        let blocked = *(&raw const crate::__sig_blocked_mask);
        let mut repost: u64 = 0;
        let mut dispatched: i32 = 0;

        for sig in 1..NSIG as i32 {
            if bits & (1u64 << sig) == 0 {
                continue;
            }

            // Check blocked mask — if blocked, re-raise later
            if blocked & (1u32 << sig) != 0 {
                repost |= 1u64 << sig;
                continue;
            }

            let handler = crate::__sig_handlers[sig as usize].load(Ordering::SeqCst);
            if handler == SIG_IGN {
                // Ignore
            } else if handler == SIG_DFL {
                if sig_default_action(sig) {
                    crate::proc::posix_exit(128 + sig);
                }
            } else {
                // Save blocked mask, apply sa_mask | self
                let saved_mask = *(&raw const crate::__sig_blocked_mask);
                let sa_mask = (*(&raw const crate::__sig_sa_mask))[sig as usize];
                (*(&raw mut crate::__sig_blocked_mask)) = saved_mask | sa_mask | (1u32 << sig);

                // SA_RESETHAND: reset to SIG_DFL after first delivery
                let sa_flags = (*(&raw const crate::__sig_sa_flags))[sig as usize];
                if sa_flags & SA_RESETHAND != 0 {
                    crate::__sig_handlers[sig as usize].store(SIG_DFL, Ordering::SeqCst);
                    // Notify procmgr of disposition change
                    let mut msg = TronaMsg::zeroed();
                    let mut reply = TronaMsg::zeroed();
                    msg.label = PM_SIGACTION;
                    msg.length = 2;
                    msg.regs[0] = sig as u64;
                    msg.regs[1] = SIG_DISP_DFL;
                    let _ = trona::ipc::call_ctx(
                        crate::tls::current_ipc_ctx(),
                        CAP_PROCMGR_EP,
                        &raw const msg,
                        &raw mut reply,
                    );
                }

                // Call the handler function
                let func: unsafe extern "C" fn(i32) = ::core::mem::transmute(handler);
                func(sig);

                // Restore blocked mask
                (*(&raw mut crate::__sig_blocked_mask)) = saved_mask;
            }
            dispatched += 1;
        }

        // Re-raise blocked signals so they remain pending
        if repost != 0 {
            trona::syscall::syscall(SYS_SIGNAL, CAP_SIGNAL_NTFN, repost, 0, 0, 0, 0);
        }

        dispatched
    }
}

/// Dispatch signal handlers from notification bits.
///
/// Shared logic between `posix_sigcheck` (cooperative) and
/// `__signal_dispatcher` (kernel-injected). Returns the number of
/// signals dispatched. Sets `__sig_last_restart` to `true` if all
/// delivered signals had `SA_RESTART` set.
unsafe fn dispatch_signal_bits(bits: u64) -> i32 {
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
                // Ignore
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
                    msg.label = PM_SIGACTION;
                    msg.length = 2;
                    msg.regs[0] = sig as u64;
                    msg.regs[1] = SIG_DISP_DFL;
                    let _ = trona::ipc::call_ctx(
                        crate::tls::current_ipc_ctx(),
                        CAP_PROCMGR_EP,
                        &raw const msg,
                        &raw mut reply,
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
            trona::syscall::syscall(SYS_SIGNAL, CAP_SIGNAL_NTFN, repost, 0, 0, 0, 0);
        }

        // Record whether all delivered signals had SA_RESTART
        (*(&raw mut crate::__sig_last_restart)) = dispatched > 0 && !any_no_restart;

        dispatched
    }
}

/// Kernel-invoked signal dispatcher entry point.
///
/// Called when the kernel interrupts a blocking IPC Call due to a bound
/// notification. The kernel pushes a notification frame onto the user stack and
/// redirects execution here with the frame pointer as the first argument.
///
/// After dispatching signal handlers, calls `SYS_NOTIF_RETURN` to restore
/// the original context. The interrupted syscall returns EINTR.
/// SA_RESTART is handled at the POSIX wrapper level, not here.
///
/// # Safety
/// `frame_ptr` must point to a valid, kernel-constructed notification frame.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __signal_dispatcher(frame_ptr: *mut SigFrame) {
    unsafe {
        sig_init();

        let frame = &mut *frame_ptr;
        if frame.magic != NOTIFFRAME_MAGIC {
            crate::proc::posix_exit(128 + 11); // SIGSEGV
        }

        let bits = frame.notification_bits;
        if bits != 0 {
            dispatch_signal_bits(bits);
        }

        // Restore original context via notif_return (returns EINTR to caller)
        trona::syscall::syscall(SYS_NOTIF_RETURN, frame_ptr as u64, 0, 0, 0, 0, 0);

        // Should never reach here
        ::core::hint::unreachable_unchecked();
    }
}
