// SPDX-License-Identifier: GPL-2.0-only
//
//! Cross-broker badge layout helpers.
//!
//! Every single-master broker (namesrv / rsrcsrv) and per-client server
//! (mmsrv / vfs / console / saltyfs daemon / posix_ttysrv) receives an
//! `MpRecord` whose `badge` field is the kernel-propagated 64-bit value
//! that init minted on the caller's server cap. The wire layout is
//! shared across all consumers so that `client_id` and `policy_id`
//! always sit in the same bit positions:
//!
//! ```text
//!   bit 63-62: class — broker-specific 2-bit tag
//!              (00 / 01 / 10 / 11). The legacy assignment used by
//!              namesrv is `00=Query / 01=Publisher / 11=Admin`;
//!              other brokers may map the bits differently but must
//!              not redistribute their meaning across other ranges.
//!   bit 61-48: reserved (= 0). Brokers MAY repurpose these bits for
//!              broker-private flags but the helper functions here
//!              assume zero.
//!   bit 47-32: policy_id (16 bits) — stable per-service id from the
//!              service manifest; survives restarts.
//!   bit 31-0:  client_id (32 bits) — caller process identity, used
//!              both for routing (every label) and as the OwnerTable
//!              key (publisher / quota tier). For publisher caps, init
//!              mints the badge with the publisher process's main TCB
//!              `trace_id` packed into this field; conceptually that
//!              value is the caller's `client_id`.
//! ```
//!
//! `BadgeClass` enums remain broker-private so the class bits can carry
//! broker-specific meaning, but every broker uses [`client_id_of`] and
//! [`policy_id_of`] to extract the shared low / mid fields.

pub const CLIENT_ID_MASK: u64 = 0xFFFF_FFFF;
pub const POLICY_ID_SHIFT: u32 = 32;
pub const POLICY_ID_MASK: u64 = 0xFFFF << POLICY_ID_SHIFT;
pub const CLASS_SHIFT: u32 = 62;
pub const CLASS_MASK: u64 = 0x3 << CLASS_SHIFT;

#[inline]
pub const fn client_id_of(badge: u64) -> u32 {
    (badge & CLIENT_ID_MASK) as u32
}

#[inline]
pub const fn policy_id_of(badge: u64) -> u32 {
    ((badge & POLICY_ID_MASK) >> POLICY_ID_SHIFT) as u32
}

#[inline]
pub const fn class_bits(badge: u64) -> u8 {
    ((badge & CLASS_MASK) >> CLASS_SHIFT) as u8
}

pub const BADGE_CLASS_QUERY: u8 = 0b00;
pub const BADGE_CLASS_PUBLISHER: u8 = 0b01;
pub const BADGE_CLASS_RESERVED: u8 = 0b10;
pub const BADGE_CLASS_ADMIN: u8 = 0b11;
