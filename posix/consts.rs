// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX personality constants — re-exports from `trona_protocol::posix_abi`
//! for the wire-shaped subset, plus personality-private definitions
//! (signals, sigaction flags, POSIX clock ids, rlimit ids) that
//! neutral subsystems must NOT depend on.
//!
//! POSIX wrappers in this crate continue to import constants through
//! `trona_posix::consts::*` unchanged; the underlying split keeps the
//! POSIX-shaped wire ABI in `trona_protocol::posix_abi` so that
//! personality-neutral servers (init / netsrv / dispdrv / procmgr /
//! win32_csrss) can depend on the same numeric encoding without
//! reaching into the POSIX personality crate.

// ---------------------------------------------------------------------------
// POSIX-shaped wire ABI — sourced from trona_protocol::posix_abi.
// ---------------------------------------------------------------------------

pub use trona_protocol::posix_abi::file::*;
pub use trona_protocol::posix_abi::mm::*;
pub use trona_protocol::posix_abi::socket::*;
pub use trona_protocol::posix_abi::tty::*;

// ---------------------------------------------------------------------------
// POSIX personality-private — neutral subsystems must NOT depend on these.
// ---------------------------------------------------------------------------

// Signal numbers
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGABRT: i32 = 6;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const NSIG: usize = 32;

// Signal disposition categories
pub const SIG_DISP_DFL: u64 = 0;
pub const SIG_DISP_IGN: u64 = 1;
pub const SIG_DISP_CATCH: u64 = 2;

// POSIX `clockid_t` values for `clock_gettime` / `clock_nanosleep`.
// These are the personality-level POSIX clock identifiers; the
// kernel-side enumeration lives in `uapi::KERNITE_CLOCK_ID_*`.
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

// sigaction flags
pub const SA_RESETHAND: i32 = 0x80000000u32 as i32;
pub const SA_RESTART: i32 = 0x10000000;

// Resource limits
pub const RLIMIT_NOFILE: u32 = 0;
pub const RLIMIT_NPROC: u32 = 1;
pub const RLIMIT_AS: u32 = 2;
pub const RLIMIT_FSIZE: u32 = 3;
pub const RLIMIT_STACK: u32 = 4;
pub const RLIMIT_CPU: u32 = 5;
pub const RLIMIT_CORE: u32 = 6;
pub const RLIMIT_DATA: u32 = 7;
pub const RLIM_NLIMITS: usize = 8;
pub const RLIM_INFINITY: u64 = u64::MAX;
