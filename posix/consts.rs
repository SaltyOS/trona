//! POSIX personality constants — file flags, signals, sockets, poll, mmap, etc.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Included from `uapi/consts/posix.rs` and `uapi/protocol/posix.rs`.
//! Non-POSIX subsystems must NOT depend on these constants.

include!("../uapi/consts/posix.rs");
include!("../uapi/protocol/posix.rs");
