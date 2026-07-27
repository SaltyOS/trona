// SPDX-License-Identifier: GPL-2.0-only
//
//! Thread / TLS / sync primitives. POSIX threads + sync (Mutex,
//! Condvar, RWLock, Barrier, Semaphore, Once) implementations live
//! here; the POSIX wrapper (`trona_posix`) sits on top.

pub(crate) mod cap;
pub mod sync;
#[allow(clippy::module_inception)]
pub mod thread;
pub mod tls;
pub mod worker;

pub use thread::{SpawnConfig, SpawnError, ThreadHandle, spawn_fn, thread_exit};
