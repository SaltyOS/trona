//! Compatibility re-export of trona UAPI constants.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! The canonical source of truth now lives in `trona/uapi/consts.rs`.
//! Keep this module as a thin forwarding layer while userland is migrated.

include!("../uapi/consts.rs");
