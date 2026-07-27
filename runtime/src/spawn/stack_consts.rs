// SPDX-License-Identifier: GPL-2.0-only
//
//! Stack provisioning constants for the substrate stack planner.
//!
//! These bounds gate the `[Memory]` manifest defaults applied when a
//! `.service` file omits `StackReserveKiB` / `StackPrefaultKiB` /
//! `StackGuardKiB`. The layout planner converts KiB → page counts via
//! `STACK_PAGE_KIB`.

/// Default usable reserve per process (1 MiB).
pub const DEFAULT_STACK_RESERVE_KIB: u32 = 1024;

/// Default top-of-stack prefaulted range (eagerly committed).
pub const DEFAULT_STACK_PREFAULT_KIB: u16 = 16;

/// Default unmapped guard hole size below the reserve base.
pub const DEFAULT_STACK_GUARD_KIB: u16 = 4;

/// Minimum valid reserve — below this a deep-call service almost
/// always faults, so a request this small is almost certainly a typo.
pub const MIN_STACK_RESERVE_KIB: u32 = 16;

/// Upper bound on reserve — protects layout against pathological
/// manifest values. 16 MiB is well above the largest VFS / netsrv
/// call chains yet still fits comfortably in the user VA stack slot.
pub const MAX_STACK_RESERVE_KIB: u32 = 16 * 1024;

/// Prefault must be at least one page. Upper bound caps eager commit
/// to keep spawn-time PMM pressure bounded.
pub const MIN_STACK_PREFAULT_KIB: u16 = 4;
pub const MAX_STACK_PREFAULT_KIB: u16 = 64;

/// Guard hole is at minimum one page; larger guards catch deeper SP
/// probes from unusual compilers.
pub const MIN_STACK_GUARD_KIB: u16 = 4;
pub const MAX_STACK_GUARD_KIB: u16 = 64;

/// Page-granularity used by all stack KiB → page conversions.
pub const STACK_PAGE_KIB: u32 = 4;
