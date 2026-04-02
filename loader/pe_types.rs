//! PE/COFF type re-exports for the loader crate.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All PE types are defined in `trona::types` (via `uapi/types/pe.rs`) and
//! re-exported here for convenience within the loader crate.

pub use trona::types::pe::{
    BaseRelocation, CoffHeader, DataDirectory, DosHeader, ImportDescriptor, OptionalHeader64,
    PeLoadResult, SectionHeader,
};
