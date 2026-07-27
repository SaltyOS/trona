// SPDX-License-Identifier: GPL-2.0-only
//
//! Process runtime service-client surfaces — VFS / MM / namesrv
//! lazy-resolve client wrappers, well-known cap getters, lazy
//! lookup machinery.

pub mod caps;
pub mod lazy_resolve;
pub mod ldsrv;
pub mod mm;
pub mod vfs;
