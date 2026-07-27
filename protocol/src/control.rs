// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-client control-capability badge layout.
//!
//! A *control capability* is a badged, non-`GRANT` capability to a
//! server's existing master endpoint. Both authority and target
//! identity ride on the badge, which the kernel stamps onto the
//! delivered record only on invoke — so the server learns *which*
//! client an admin verb targets, and that the caller is `init` (the
//! sole holder of control caps), in one unforgeable step. `init` (which
//! encodes the ROOT badge) and the per-client servers (`mmsrv` / `vfs`,
//! which decode) all consult this one codec so the bit layout cannot
//! drift.
//!
//! ```text
//!   bits [63:60] = 0xC          control-cap tag (disjoint from the 0xF
//!                               privileged-class admin badges and the
//!                               0x4 publisher-class client badges)
//!   bit  [59]    = ROOT         1 = the register-only root cap;
//!                               0 = a per-client cap
//!   bits [58:16] = epoch        per-slot reuse counter (43 bits)
//!   bits [15: 0] = slot         client arena slot index (<= 65535)
//! ```
//!
//! The ROOT cap is `tag | ROOT` with `slot` / `epoch` zero; it
//! authorizes only `REGISTER_CLIENT`. A per-client cap carries the
//! client's arena `slot` and the slot's `epoch` captured at mint time;
//! the server's `resolve_control` rejects a badge whose epoch no longer
//! matches the slot's current value, so a cap for a recycled slot fails
//! closed. The 43-bit epoch makes reuse-to-collision unreachable in
//! practice.

/// Tag nibble occupying bits `[63:60]`.
pub const CONTROL_TAG: u64 = 0xC;
pub const TAG_SHIFT: u32 = 60;
pub const TAG_MASK: u64 = 0xF << TAG_SHIFT;

/// Root marker at bit `[59]`.
pub const ROOT_SHIFT: u32 = 59;
pub const ROOT_BIT: u64 = 1 << ROOT_SHIFT;

/// Epoch field at bits `[58:16]` (43 bits).
pub const EPOCH_SHIFT: u32 = 16;
pub const EPOCH_BITS: u32 = 43;
pub const EPOCH_MAX: u64 = (1u64 << EPOCH_BITS) - 1;
pub const EPOCH_MASK: u64 = EPOCH_MAX << EPOCH_SHIFT;

/// Slot field at bits `[15:0]` (16 bits).
pub const SLOT_MASK: u64 = 0xFFFF;
pub const SLOT_MAX: u32 = 0xFFFF;

/// True when `badge`'s tag nibble is the control-cap tag.
#[inline]
pub const fn tag_matches(badge: u64) -> bool {
    (badge & TAG_MASK) == (CONTROL_TAG << TAG_SHIFT)
}

/// True for the register-only ROOT control cap.
#[inline]
pub const fn is_root(badge: u64) -> bool {
    tag_matches(badge) && (badge & ROOT_BIT) != 0
}

/// Arena slot index encoded in `badge` (low 16 bits).
#[inline]
pub const fn slot_of(badge: u64) -> u16 {
    (badge & SLOT_MASK) as u16
}

/// Per-slot epoch encoded in `badge` (bits `[58:16]`).
#[inline]
pub const fn epoch_of(badge: u64) -> u64 {
    (badge >> EPOCH_SHIFT) & EPOCH_MAX
}

/// Encode a per-client control-cap badge for arena `slot` whose current
/// reuse counter is `epoch`. The epoch is masked to 43 bits; the ROOT bit
/// is clear, so this never collides with [`encode_root`].
#[inline]
pub const fn encode(slot: u16, epoch: u64) -> u64 {
    (CONTROL_TAG << TAG_SHIFT) | ((epoch & EPOCH_MAX) << EPOCH_SHIFT) | (slot as u64)
}

/// Encode the per-server ROOT control-cap badge (slot / epoch zero).
#[inline]
pub const fn encode_root() -> u64 {
    (CONTROL_TAG << TAG_SHIFT) | ROOT_BIT
}

/// Advance a per-slot epoch: increment, mask to the 43-bit field, and skip
/// the 0 sentinel on wrap. `0` is reserved to mean "no control cap".
#[inline]
pub const fn next_epoch(epoch: u64) -> u64 {
    let n = epoch.wrapping_add(1) & EPOCH_MAX;
    if n == 0 { 1 } else { n }
}
