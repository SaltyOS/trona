//! trona_win32 -- Win32 API compatibility layer for SaltyOS
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides minimal Win32 console API for PE binaries running on SaltyOS.
//! Functions are exported with `#[unsafe(no_mangle)]` so PE import tables
//! can reference them directly.
//!
//! # Architecture
//!
//! Console I/O (WriteConsoleA/W, ReadConsoleA) delegates to the win32_csrss
//! server via IPC, which in turn forwards to the console server.
//!
//! For the minimal implementation, standard handles map directly
//! to VFS file descriptors 0/1/2 (stdin/stdout/stderr), and console
//! writes go through the Win32 CSRSS server.

#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(linkage)]

extern crate trona;

pub mod console;
pub mod crt;
pub mod error;
pub mod handle;
pub mod protocol;
pub mod process;

// Re-exports for convenience
pub use handle::HANDLE;
pub use protocol::*;
