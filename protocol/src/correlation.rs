// SPDX-License-Identifier: GPL-2.0-only
//
//! Correlation header — 4-word `regs[]` stamp every backend RPC and
//! its reply carries to identify the originating PendingOp.
//!
//! Wire layout: the last four register slots of the IPC message
//! (regs[28..=31]) hold an encoded `CorrelationHeader`. The header
//! gives the completion router three properties:
//! 1. Token-based PendingOp lookup — `token` is the TxId stamped
//!    at issue time.
//! 2. Session-incarnation check — `session` is the backend session
//!    id at issue time. After teardown + reopen, an old reply
//!    arriving with the previous session id is dropped at the
//!    5-tuple check before the resume payload is decoded.
//! 3. Class / backend tag — distinguishes saltyfs replies from
//!    netsrv / posix_ttysrv / pager replies on the same callback
//!    EP, so a misrouted reply is detected in O(1) against the
//!    typed `class` byte.
//!
//! The kernel never inspects these fields — they're a userland
//! convention between vfs and the backends it talks to.

/// Last four registers of the IPC `regs[32]` array carry the
/// header. Picked at the end so backend payload encoding can
/// claim the low slots without coordinating with vfs's offset.
pub const CORRELATION_HEADER_REG_START: usize = 28;

/// Number of `regs[]` slots the header occupies (4 × u64).
pub const CORRELATION_HEADER_REG_COUNT: usize = 4;

/// Minimum `msg.length` that any IPC request / reply carrying a
/// correlation header must declare. The kernel only forwards the
/// first `length` registers, so a stamp without a wire-length
/// raise gets dropped before the receiver can see it.
pub const CORRELATION_WIRE_LENGTH: u8 = 32;

pub const CORRELATION_CLASS_FS: u8 = 0x01;
pub const CORRELATION_CLASS_NET: u8 = 0x02;
pub const CORRELATION_CLASS_PTY: u8 = 0x03;
pub const CORRELATION_CLASS_PAGER: u8 = 0x04;
pub const CORRELATION_CLASS_DEV: u8 = 0x05;

pub const CORRELATION_BACKEND_SALTYFS: u8 = 0x01;
pub const CORRELATION_BACKEND_TMPFS: u8 = 0x02;
pub const CORRELATION_BACKEND_RAMFS: u8 = 0x03;
pub const CORRELATION_BACKEND_NETSRV: u8 = 0x04;
pub const CORRELATION_BACKEND_POSIX_TTYSRV: u8 = 0x05;
pub const CORRELATION_BACKEND_DISPDRV: u8 = 0x06;

pub const CORRELATION_KIND_REQUEST: u8 = 0x01;
pub const CORRELATION_KIND_COMPLETION: u8 = 0x02;

/// Header flag — backend reports the request landed against a
/// stale session incarnation (session_id mismatch). Completion
/// router translates to `VfsError::StaleIncarnation`.
pub const CORRELATION_F_STALE_INCARNATION: u8 = 1 << 0;

/// Header flag — `BACKEND_LOOKUP` request resolves the **parent**
/// of `regs[0]` (treated as a child inode) instead of the usual
/// `(parent_ino, name)` walk. Used by the dotdot-walk async path
/// so a single round-trip replaces the legacy
/// `getparent + stat` pair.
pub const CORRELATION_F_LOOKUP_PARENT: u8 = 1 << 1;

/// 4-word stamp identifying the originating PendingOp and its
/// session context. Encoded into `regs[28..=31]` on every backend
/// request and echoed in every backend reply.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CorrelationHeader {
    pub class: u8,
    pub backend: u8,
    pub kind: u8,
    pub flags: u8,
    pub session: u32,
    pub opcode: u16,
    /// Reserved for future header growth — wire encodes as 0.
    pub _reserved0: u16,
    pub token: u64,
    pub request_seq: u32,
    pub request_seq_secondary: u32,
}

impl CorrelationHeader {
    /// Encode into four contiguous u64 words ready to drop into
    /// the `regs[]` array. Layout (LSB → MSB per word):
    ///   word 0: class | backend << 8 | kind << 16 | flags << 24 |
    ///           session << 32
    ///   word 1: opcode | _reserved0 << 16
    ///   word 2: token (full u64).
    ///   word 3: request_seq | request_seq_secondary << 32
    #[inline]
    pub fn encode_words(&self) -> [u64; CORRELATION_HEADER_REG_COUNT] {
        let w0 = (self.class as u64)
            | ((self.backend as u64) << 8)
            | ((self.kind as u64) << 16)
            | ((self.flags as u64) << 24)
            | ((self.session as u64) << 32);
        let w1 = (self.opcode as u64) | ((self._reserved0 as u64) << 16);
        let w2 = self.token;
        let w3 = (self.request_seq as u64) | ((self.request_seq_secondary as u64) << 32);
        [w0, w1, w2, w3]
    }

    /// Inverse of [`encode_words`].
    #[inline]
    pub fn decode_words(words: [u64; CORRELATION_HEADER_REG_COUNT]) -> Self {
        let class = (words[0] & 0xFF) as u8;
        let backend = ((words[0] >> 8) & 0xFF) as u8;
        let kind = ((words[0] >> 16) & 0xFF) as u8;
        let flags = ((words[0] >> 24) & 0xFF) as u8;
        let session = ((words[0] >> 32) & 0xFFFF_FFFF) as u32;
        let opcode = (words[1] & 0xFFFF) as u16;
        let _reserved0 = ((words[1] >> 16) & 0xFFFF) as u16;
        let token = words[2];
        let request_seq = (words[3] & 0xFFFF_FFFF) as u32;
        let request_seq_secondary = ((words[3] >> 32) & 0xFFFF_FFFF) as u32;
        Self {
            class,
            backend,
            kind,
            flags,
            session,
            opcode,
            _reserved0,
            token,
            request_seq,
            request_seq_secondary,
        }
    }
}

/// Defence-in-depth: any wire-side caller that stamps a
/// correlation header must leave `msg.length >=
/// CORRELATION_WIRE_LENGTH` so the kernel forwards the trailing
/// header words. This helper raises the length without overriding
/// a higher value the caller already set. Caller passes
/// `&mut msg.length` directly so the helper stays free of any
/// kernel-ABI struct dependency — the same `trona_protocol` rmeta
/// compiles on saltyos and PE targets without cfg gates.
#[inline]
pub fn ensure_correlation_wire_length(length: &mut u64) {
    if (*length as usize) < (CORRELATION_HEADER_REG_START + CORRELATION_HEADER_REG_COUNT) {
        *length = CORRELATION_WIRE_LENGTH as u64;
    }
}
