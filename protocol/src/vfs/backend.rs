// SPDX-License-Identifier: GPL-2.0-only
//
//! VFS backend wire (block 0x600..=0x6FF). Inter-server contract
//! between vfs (caller) and the per-mount backend daemons (saltyfs,
//! netsrv, blkdrv, posix_ttysrv pty pair). Defined here — not in
//! vfs's crate — because backend daemons (saltyfs, future ext4) are
//! driver crates that cannot depend on vfs; both sides import the
//! literal label values from `trona_protocol::vfs::backend`. vfs's
//! own `ipc/protocol/backend.rs` re-exports these constants and
//! adds vfs-side helpers.
//!
//! Wire summary:
//! * `BACKEND_OPEN_SESSION(mount_flags) -> (max_inflight,
//!   shm_region_mo)`. vfs negotiates per-mount-instance state with
//!   the backend.
//! * `BACKEND_CLOSE_SESSION(session_id) -> errno`. Final teardown
//!   step 4 in vfs's session lifecycle.
//! * Metadata RPCs: `BACKEND_LOOKUP / STAT / GETINFO / READLINK`.
//! * Mutation RPCs: `BACKEND_CREATE / MKDIR / SYMLINK / UNLINK /
//!   RMDIR / RENAME / LINK / TRUNCATE / SETMODE / SETOWNER /
//!   SETTIMES / SETATTR`.
//! * Bulk RPCs (TransferDescriptor over per-mount SHM ring):
//!   `BACKEND_READ / WRITE / READDIR`.
//! * xattr RPCs: `BACKEND_GETXATTR / SETXATTR / LISTXATTR /
//!   REMOVEXATTR`.
//! * Ordering / cancel: `BACKEND_FSYNC / DRAIN / CANCEL`.
//!
//! Reply labels (`VFS_BACKEND_REPLY_*`) sit outside the request
//! block (0x6F02..=0x6F7A) so a malformed reply that echoes a
//! request label is detected as malformed rather than misrouted.

pub const VFS_BACKEND_OPEN_SESSION: u64 = 0x600;
pub const VFS_BACKEND_CLOSE_SESSION: u64 = 0x601;
pub const VFS_BACKEND_LOOKUP: u64 = 0x602;
pub const VFS_BACKEND_STAT: u64 = 0x603;
pub const VFS_BACKEND_READ: u64 = 0x604;
pub const VFS_BACKEND_WRITE: u64 = 0x605;
pub const VFS_BACKEND_READDIR: u64 = 0x606;
pub const VFS_BACKEND_READLINK: u64 = 0x607;
pub const VFS_BACKEND_GETXATTR: u64 = 0x608;
pub const VFS_BACKEND_SETXATTR: u64 = 0x609;
pub const VFS_BACKEND_LISTXATTR: u64 = 0x60A;
pub const VFS_BACKEND_CREATE: u64 = 0x60B;
pub const VFS_BACKEND_MKDIR: u64 = 0x60C;
pub const VFS_BACKEND_SYMLINK: u64 = 0x60D;
pub const VFS_BACKEND_UNLINK: u64 = 0x60E;
pub const VFS_BACKEND_RMDIR: u64 = 0x60F;
pub const VFS_BACKEND_RENAME: u64 = 0x610;
pub const VFS_BACKEND_LINK: u64 = 0x611;
pub const VFS_BACKEND_TRUNCATE: u64 = 0x612;
pub const VFS_BACKEND_SETMODE: u64 = 0x613;
pub const VFS_BACKEND_SETOWNER: u64 = 0x614;
pub const VFS_BACKEND_SETTIMES: u64 = 0x615;
pub const VFS_BACKEND_FSYNC: u64 = 0x616;
pub const VFS_BACKEND_DRAIN: u64 = 0x617;
pub const VFS_BACKEND_CANCEL: u64 = 0x618;
pub const VFS_BACKEND_GETINFO: u64 = 0x619;
pub const VFS_BACKEND_REMOVEXATTR: u64 = 0x61A;
pub const VFS_BACKEND_SETATTR: u64 = 0x61B;
/// Bulk-region SHM setup. vfs allocates the SHM region (frame
/// retype + own vspace map), then transfers the MO cap to the
/// backend via `BACKEND_SHM_SETUP` so the backend can map the same
/// region into its own vspace. Reply is a typed ack — no caps
/// flow back. vfs retains the master MO cap so teardown can revoke
/// the daemon's view by destroying the MO.
pub const VFS_BACKEND_SHM_SETUP: u64 = 0x61C;

pub const VFS_BACKEND_REPLY_OK: u64 = 0;
pub const VFS_BACKEND_REPLY_NOT_FOUND: u64 = 0x6F02;
pub const VFS_BACKEND_REPLY_IO_ERROR: u64 = 0x6F05;
pub const VFS_BACKEND_REPLY_PERM: u64 = 0x6F0D;
pub const VFS_BACKEND_REPLY_NO_SPACE: u64 = 0x6F1C;
pub const VFS_BACKEND_REPLY_EXIST: u64 = 0x6F11;
pub const VFS_BACKEND_REPLY_NOT_DIR: u64 = 0x6F14;
pub const VFS_BACKEND_REPLY_IS_DIR: u64 = 0x6F15;
pub const VFS_BACKEND_REPLY_NOT_EMPTY: u64 = 0x6F27;
pub const VFS_BACKEND_REPLY_NAME_TOO_LONG: u64 = 0x6F24;
pub const VFS_BACKEND_REPLY_INVALID: u64 = 0x6F16;
pub const VFS_BACKEND_REPLY_LOOP: u64 = 0x6F28;
pub const VFS_BACKEND_REPLY_RO_FS: u64 = 0x6F1E;
pub const VFS_BACKEND_REPLY_QUOTA: u64 = 0x6F7A;
pub const VFS_BACKEND_REPLY_X_DEV: u64 = 0x6F12;
pub const VFS_BACKEND_REPLY_BUSY: u64 = 0x6F10;
pub const VFS_BACKEND_REPLY_NOT_SUPPORTED: u64 = 0x6F26;

// Backend label aliases — wire labels above are the qualified
// names used by external callers (substrate consumers, future
// shared crates). vfs and saltyfs daemon both reach for the
// short names below through `use trona_protocol::vfs::backend::*`.
// Drift against the qualified names is zero because these are
// direct re-exports.
pub use VFS_BACKEND_CANCEL as BACKEND_CANCEL;
pub use VFS_BACKEND_CLOSE_SESSION as BACKEND_CLOSE_SESSION;
pub use VFS_BACKEND_CREATE as BACKEND_CREATE;
pub use VFS_BACKEND_DRAIN as BACKEND_DRAIN;
pub use VFS_BACKEND_FSYNC as BACKEND_FSYNC;
pub use VFS_BACKEND_GETINFO as BACKEND_GETINFO;
pub use VFS_BACKEND_GETXATTR as BACKEND_GETXATTR;
pub use VFS_BACKEND_LINK as BACKEND_LINK;
pub use VFS_BACKEND_LISTXATTR as BACKEND_LISTXATTR;
pub use VFS_BACKEND_LOOKUP as BACKEND_LOOKUP;
pub use VFS_BACKEND_MKDIR as BACKEND_MKDIR;
pub use VFS_BACKEND_OPEN_SESSION as BACKEND_OPEN_SESSION;
pub use VFS_BACKEND_READ as BACKEND_READ;
pub use VFS_BACKEND_READDIR as BACKEND_READDIR;
pub use VFS_BACKEND_READLINK as BACKEND_READLINK;
pub use VFS_BACKEND_REMOVEXATTR as BACKEND_REMOVEXATTR;
pub use VFS_BACKEND_RENAME as BACKEND_RENAME;
pub use VFS_BACKEND_RMDIR as BACKEND_RMDIR;
pub use VFS_BACKEND_SETATTR as BACKEND_SETATTR;
pub use VFS_BACKEND_SETMODE as BACKEND_SETMODE;
pub use VFS_BACKEND_SETOWNER as BACKEND_SETOWNER;
pub use VFS_BACKEND_SETTIMES as BACKEND_SETTIMES;
pub use VFS_BACKEND_SETXATTR as BACKEND_SETXATTR;
pub use VFS_BACKEND_STAT as BACKEND_STAT;
pub use VFS_BACKEND_SYMLINK as BACKEND_SYMLINK;
pub use VFS_BACKEND_TRUNCATE as BACKEND_TRUNCATE;
pub use VFS_BACKEND_UNLINK as BACKEND_UNLINK;
pub use VFS_BACKEND_WRITE as BACKEND_WRITE;

// Legacy daemon-facing aliases. saltyfs daemon's dispatch refers
// to the historic POSIX-y verb names; the wire numeric is the
// same as the SETMODE / SETOWNER labels above (no fresh slot).
pub use VFS_BACKEND_SETMODE as BACKEND_CHMOD;
pub use VFS_BACKEND_SETOWNER as BACKEND_CHOWN;
pub use VFS_BACKEND_SHM_SETUP as BACKEND_SHM_SETUP;

// Backend wire register layout. Constants (not labels) — placed
// here because the saltyfs daemon and the vfs caller both decode
// the same register positions, so a single source of truth keeps
// the wire byte layout in sync.

/// `regs[]` index where READ / WRITE encode the
/// [`TransferDescriptor`]. Slots 0..=3 carry ino / file_offset /
/// pre-descriptor scratch and slot 31 carries the correlation
/// header tail. The descriptor occupies
/// [`TransferDescriptor::REG_COUNT`] register slots starting at
/// this offset (regs[4..8]).
pub const BACKEND_RW_REQ_DESCRIPTOR_REG: usize = 4;

/// `regs[]` index of the inline READ payload window. The first 16
/// bytes (regs[7..=8]) are reserved for inline header continuation.
pub const BACKEND_READ_INLINE_PAYLOAD_REG: usize = 8;

/// `regs[]` index of the inline WRITE payload window. Mirrors
/// [`BACKEND_READ_INLINE_PAYLOAD_REG`] for the WRITE direction.
pub const BACKEND_WRITE_INLINE_PAYLOAD_REG: usize = 8;

/// READDIR completion flag — backend reports the listing is fully
/// drained (no more entries past the returned cursor).
pub const BACKEND_READDIR_F_EOF: u64 = 1 << 0;

/// `BACKEND_SETATTR` request register count — bundle of mask +
/// affected fields (mode / uid / gid / size / atime / mtime).
pub const BACKEND_SETATTR_REG_COUNT: usize = 11;

pub const SETATTR_MASK_MODE: u32 = 1 << 0;
pub const SETATTR_MASK_UID: u32 = 1 << 1;
pub const SETATTR_MASK_GID: u32 = 1 << 2;
pub const SETATTR_MASK_ATIME: u32 = 1 << 3;
pub const SETATTR_MASK_MTIME: u32 = 1 << 4;
pub const SETATTR_MASK_SIZE: u32 = 1 << 5;

/// `BACKEND_SETATTR` reply register count — echo of the post-commit
/// stat fields the caller needed without a follow-up STAT.
pub const BACKEND_SETATTR_REPLY_REG_COUNT: u64 = 8;

// Backend feature flags (bit field stored in
// `BACKEND_OPEN_SESSION` reply). The session reply advertises the
// backend's supported feature set so the caller can pick the
// best-available encoding (inline vs SHM transfer, async vs
// synchronous reply, incarnation-seq stale-detect, etc).

/// Backend supports async-V1 protocol (typed per-call CorrelationHeader,
/// out-of-order replies, in-flight credit accounting).
pub const BACKEND_FEATURE_ASYNC_V1: u64 = 1 << 0;

/// Backend stamps a session-incarnation sequence on every request
/// and reply, allowing the caller to drop stale-incarnation replies
/// at the 5-tuple check.
pub const BACKEND_FEATURE_INCARNATION_SEQ: u64 = 1 << 1;

/// Backend accepts inline READ / WRITE payload (bytes packed into
/// the IPC buffer regs window past the descriptor).
pub const BACKEND_FEATURE_INLINE_TRANSFER: u64 = 1 << 2;

/// Backend accepts SHM-relayed READ / WRITE payload via the
/// per-mount-instance ring advertised in
/// `BACKEND_OPEN_SESSION` reply.
pub const BACKEND_FEATURE_SHM_TRANSFER: u64 = 1 << 3;

/// Inline READ / WRITE payload window cap. The descriptor occupies
/// `regs[BACKEND_RW_REQ_DESCRIPTOR_REG..BACKEND_RW_REQ_DESCRIPTOR_REG +
/// TransferDescriptor::REG_COUNT]` (= regs[4..6]); slots [6..8) are
/// reserved scratch; payload bytes start at
/// `BACKEND_READ_INLINE_PAYLOAD_REG` (= regs[8]) and run to the
/// correlation header tail at `regs[28]`. That leaves 20 register
/// slots × 8 bytes = 160 bytes for the inline window.
pub const INLINE_TRANSFER_WIRE_MAX: u64 = 160;

/// `TransferDescriptor::kind` discriminator — payload is packed
/// inline in the IPC buffer past the descriptor. Caller must
/// honour [`INLINE_TRANSFER_WIRE_MAX`].
pub const TRANSFER_KIND_INLINE: u64 = 0;

/// `TransferDescriptor::kind` discriminator — payload lives in the
/// per-mount-instance SHM ring at the descriptor's offset.
pub const TRANSFER_KIND_SHM: u64 = 1;

/// `TransferDescriptor::kind` discriminator — payload lives in a
/// caller-allocated MemoryObject delivered alongside the request
/// as `caps[0]`. The backend maps the MO into its own VA, reads
/// the payload, and unmaps + drops the cap on completion. Used
/// for writes / reads larger than the SHM ring sub-region size,
/// where amortising a per-call MO retype + map is cheaper than
/// stalling on a ring slot or chunking the payload across the
/// ring. Per-backend staging caps are a private implementation
/// detail (saltyfs rejects with `KERNITE_ERR_OUT_OF_RANGE` past
/// its window); the wire does not advertise a single cross-backend
/// maximum.
pub const TRANSFER_KIND_MO: u64 = 2;

/// Descriptor for the payload window of a backend READ / WRITE /
/// READDIR / XATTR call. Stored on backend RPC records as
/// [`TransferDescriptor::REG_COUNT`] consecutive register slots.
///
/// Wire layout (4 register slots): `(kind, flags, offset, length)`.
///
/// * `kind` — one of [`TRANSFER_KIND_INLINE`], [`TRANSFER_KIND_SHM`],
///   [`TRANSFER_KIND_MO`].
/// * `flags` — currently reserved (must be zero).
/// * `offset` — for `SHM`, byte offset into the per-mount-instance
///   SHM ring. For `INLINE` / `MO`, must be zero.
/// * `length` — payload length in bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TransferDescriptor {
    /// Discriminator selecting the payload transport — see the
    /// `TRANSFER_KIND_*` constants.
    pub kind: u64,
    /// Reserved for future per-descriptor flags. Must be zero on
    /// the wire today; non-zero is rejected by the backend.
    pub flags: u64,
    /// For `SHM`, byte offset into the per-mount-instance SHM
    /// ring where the payload starts. Zero for `INLINE` / `MO`.
    pub offset: u64,
    /// Payload length in bytes.
    pub length: u64,
}

impl TransferDescriptor {
    /// How many `regs[]` slots a [`TransferDescriptor`] occupies on
    /// the backend RPC wire (`kind`, `flags`, `offset`, `length`).
    pub const REG_COUNT: u32 = 4;

    pub const fn inline(length: u64) -> Self {
        Self {
            kind: TRANSFER_KIND_INLINE,
            flags: 0,
            offset: 0,
            length,
        }
    }

    pub const fn shm(offset: u64, length: u64) -> Self {
        Self {
            kind: TRANSFER_KIND_SHM,
            flags: 0,
            offset,
            length,
        }
    }

    pub const fn mo(length: u64) -> Self {
        Self {
            kind: TRANSFER_KIND_MO,
            flags: 0,
            offset: 0,
            length,
        }
    }

    /// Pack the descriptor into [`Self::REG_COUNT`] consecutive
    /// `regs[]` words for wire transmission. Layout matches
    /// [`Self::decode_regs`].
    #[inline]
    pub const fn encode_regs(self) -> [u64; Self::REG_COUNT as usize] {
        [self.kind, self.flags, self.offset, self.length]
    }

    /// Inverse of [`Self::encode_regs`]. Stable with respect to
    /// round trips on the same ABI.
    #[inline]
    pub const fn decode_regs(regs: [u64; Self::REG_COUNT as usize]) -> Self {
        Self {
            kind: regs[0],
            flags: regs[1],
            offset: regs[2],
            length: regs[3],
        }
    }
}
