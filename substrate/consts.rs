//! Trona UAPI constants — grouped by namespace.
//! SPDX-License-Identifier: GPL-2.0-only

pub mod kernel {
	include!("../uapi/consts/kernel.rs");
}

pub mod posix {
	include!("../uapi/consts/posix.rs");
}

pub mod server {
	include!("../uapi/consts/server.rs");
}

pub use kernel::*;
pub use server::*;
