//! Trona UAPI protocols — grouped by subsystem/server namespace.
//! SPDX-License-Identifier: GPL-2.0-only

pub mod vfs {
    include!("../uapi/protocol/vfs.rs");
}

pub mod procmgr {
    include!("../uapi/protocol/procmgr.rs");
}

pub mod mmsrv {
    include!("../uapi/protocol/mmsrv.rs");
}

pub mod namesrv {
    include!("../uapi/protocol/namesrv.rs");
}

pub mod posix {
    include!("../uapi/protocol/posix.rs");
}

pub mod win32 {
    include!("../uapi/protocol/win32.rs");
}

pub mod server {
    include!("../uapi/protocol/server.rs");
}

pub mod rsrcsrv {
    include!("../uapi/protocol/rsrcsrv.rs");
}

pub use mmsrv::*;
pub use namesrv::*;
pub use procmgr::*;
pub use rsrcsrv::*;
pub use server::*;
pub use vfs::*;