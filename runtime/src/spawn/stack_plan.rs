//! Pure calculation for provisioning a user-process stack region.
//!
//! Given a per-service `StackLayoutSpec` and the chosen `stack_top` VA,
//! produces the concrete sizing and VA coordinates that both init (the
//! bootstrap provisioner) and mmsrv (the steady-state pager) need to
//! materialise a stack that matches memory-model-audit invariants
//! I21–I24:
//!
//! * `reserve` — full-span MO-backed VmArea, tagged
//!   `REGION_KIND_STACK`, spanning `[stack_base, stack_top)`. Every byte
//!   in this range is either present (prefault) or demand PTE.
//! * `prefault` — top-N pages of the reserve eagerly committed and
//!   present-mapped so the spawner can seed argv/envp/auxv without
//!   taking a fault on the very first instruction.
//! * `guard` — unmapped hole at `[guard_base, stack_base)`. No VmArea,
//!   no MO entry, no PTE. Overrun that reaches the guard takes a page
//!   fault with no backing VmArea and falls through to SIGSEGV.
//!
//! This module is `no_std`, allocation-free, and free of syscalls; it
//! is the single shared source of truth so init's direct-syscall path
//! and mmsrv's IPC-handler path cannot drift in what they compute.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::spawn::stack_consts::STACK_PAGE_KIB;

const PAGE_BYTES: u64 = uapi::KERNITE_PAGE_BYTES as u64;

/// Per-service stack provisioning shape, in pages.
///
/// All three fields are page counts (4 KiB each). `reserve_pages` is the
/// usable stack span; `prefault_pages` is how many of those pages are
/// eagerly committed at the top; `guard_pages` is the unmapped guard
/// hole immediately below the reserve base.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StackLayoutSpec {
    pub reserve_pages: u32,
    pub prefault_pages: u16,
    pub guard_pages: u16,
}

impl StackLayoutSpec {
    pub const fn zeroed() -> Self {
        Self {
            reserve_pages: 0,
            prefault_pages: 0,
            guard_pages: 0,
        }
    }

    /// Default provisioning values applied to a service when it omits
    /// `[Memory]` keys from its `.service` manifest.
    pub const fn default_service() -> Self {
        Self {
            reserve_pages: kib_to_pages_u32(crate::spawn::stack_consts::DEFAULT_STACK_RESERVE_KIB),
            prefault_pages: kib_to_pages_u16(
                crate::spawn::stack_consts::DEFAULT_STACK_PREFAULT_KIB,
            ),
            guard_pages: kib_to_pages_u16(crate::spawn::stack_consts::DEFAULT_STACK_GUARD_KIB),
        }
    }

    /// Build a spec from optional manifest values, substituting each
    /// field's default when the corresponding value is zero. Any
    /// out-of-range override is silently replaced with the default
    /// value; the parser in `init/src/ini.rs` is responsible for
    /// enforcing stricter validation (it emits parse warnings before
    /// reaching this call).
    pub const fn from_manifest_or_default(
        reserve_kib: u32,
        prefault_kib: u16,
        guard_kib: u16,
    ) -> Self {
        let reserve = if reserve_kib == 0 {
            crate::spawn::stack_consts::DEFAULT_STACK_RESERVE_KIB
        } else {
            reserve_kib
        };
        let prefault = if prefault_kib == 0 {
            crate::spawn::stack_consts::DEFAULT_STACK_PREFAULT_KIB
        } else {
            prefault_kib
        };
        let guard = if guard_kib == 0 {
            crate::spawn::stack_consts::DEFAULT_STACK_GUARD_KIB
        } else {
            guard_kib
        };
        Self {
            reserve_pages: kib_to_pages_u32(reserve),
            prefault_pages: kib_to_pages_u16(prefault),
            guard_pages: kib_to_pages_u16(guard),
        }
    }

    /// Reserve size in bytes.
    pub const fn reserve_bytes(&self) -> u64 {
        (self.reserve_pages as u64) * PAGE_BYTES
    }

    /// Guard hole size in bytes (may be zero).
    pub const fn guard_bytes(&self) -> u64 {
        (self.guard_pages as u64) * PAGE_BYTES
    }

    /// Sanity check: returns true only when the spec represents a
    /// valid provisioning shape (non-zero reserve, prefault within
    /// reserve).
    pub const fn is_valid(&self) -> bool {
        self.reserve_pages > 0 && (self.prefault_pages as u32) <= self.reserve_pages
    }
}

const fn kib_to_pages_u32(kib: u32) -> u32 {
    kib / STACK_PAGE_KIB
}

const fn kib_to_pages_u16(kib: u16) -> u16 {
    (kib / (STACK_PAGE_KIB as u16)) as u16
}

/// Fully-resolved provisioning coordinates for one stack region.
///
/// All VAs are page-aligned; all page counts are in 4 KiB pages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StackMaterialization {
    /// Full-capacity MO page count (equals `spec.reserve_pages`).
    pub mo_pages: u32,
    /// MO page offset at which prefault commit begins.
    pub commit_offset_pages: u32,
    /// Number of pages to `MO_COMMIT` eagerly.
    pub commit_count_pages: u32,
    /// Start of the reserve VmArea (= `stack_top - reserve_bytes`).
    pub reserve_base: u64,
    /// End of the reserve VmArea (= `stack_top`).
    pub stack_top: u64,
    /// Guard hole lower bound (inclusive). Equals `reserve_base` minus
    /// `guard_bytes`; zero when `guard_pages == 0`.
    pub guard_bottom: u64,
}

impl StackMaterialization {
    /// Byte size of the reserve VmArea.
    pub const fn reserve_bytes(&self) -> u64 {
        self.stack_top - self.reserve_base
    }
}

/// Compute the materialisation coordinates for a stack region whose
/// top VA is pinned at `stack_top`.
///
/// Returns `None` for invalid specs, for non-page-aligned `stack_top`,
/// or when the guard hole would underflow past address zero.
pub const fn plan_stack_materialization(
    spec: StackLayoutSpec,
    stack_top: u64,
) -> Option<StackMaterialization> {
    if !spec.is_valid() {
        return None;
    }
    if stack_top == 0 {
        return None;
    }
    if stack_top & (PAGE_BYTES - 1) != 0 {
        return None;
    }

    let reserve_bytes = spec.reserve_bytes();
    if reserve_bytes > stack_top {
        return None;
    }
    let reserve_base = stack_top - reserve_bytes;

    let guard_bytes = spec.guard_bytes();
    let guard_bottom = if guard_bytes == 0 {
        0
    } else if guard_bytes > reserve_base {
        return None;
    } else {
        reserve_base - guard_bytes
    };

    Some(StackMaterialization {
        mo_pages: spec.reserve_pages,
        commit_offset_pages: spec.reserve_pages - (spec.prefault_pages as u32),
        commit_count_pages: spec.prefault_pages as u32,
        reserve_base,
        stack_top,
        guard_bottom,
    })
}
