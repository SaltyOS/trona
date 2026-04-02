//! Core types for SaltyOS userland — grouped by namespace.
//! SPDX-License-Identifier: GPL-2.0-only

pub mod core {
	include!("../uapi/types/core.rs");
}

pub mod pe {
	include!("../uapi/types/pe.rs");
}

pub mod posix {
	include!("../uapi/types/posix.rs");
}

pub use core::*;
