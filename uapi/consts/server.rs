// Server-level constants: well-known service caps, spawn policy, extended errors.
// SPDX-License-Identifier: GPL-2.0-only

// Well-known capability slots are now spawner-private and delivered to each
// child via `AT_TRONA_*` auxv tags. Lib code reads them at runtime through
// the `trona::caps::*` getters; the spawner (init / procmgr) is free to
// place each cap at any cursor-allocated slot. Only `CAP_UNTYPED_START`
// remains here as a stable convention for the start of the procmgr-side
// untyped slot range.
pub const CAP_UNTYPED_START: u64 = 16;

// Spawn readiness modes (bits [1:0] of spawn_policy)
pub const SPAWN_READY_IMMEDIATE: u64 = 0;
pub const SPAWN_READY_NOTIFY: u64 = 1;

/// Build a spawn_policy bitfield from components.
///
/// Layout: bits[1:0]=readiness, bit[2]=map_initrd, bit[3]=is_display,
///         bits[15:8]=cnode_bits, bits[31:16]=memory_kb
pub const fn spawn_policy_build(
    readiness_mode: u64,
    map_initrd: bool,
    is_display: bool,
    cnode_bits: u8,
    memory_kb: u16,
) -> u64 {
    let mut p = readiness_mode & 0x3;
    if map_initrd { p |= 1 << 2; }
    if is_display { p |= 1 << 3; }
    p |= (cnode_bits as u64) << 8;
    p |= (memory_kb as u64) << 16;
    p
}

pub const fn spawn_policy_readiness(policy: u64) -> u64 {
    policy & 0x3
}

pub const fn spawn_policy_map_initrd(policy: u64) -> bool {
    (policy & (1 << 2)) != 0
}

pub const fn spawn_policy_is_display(policy: u64) -> bool {
    (policy & (1 << 3)) != 0
}

pub const fn spawn_policy_cnode_bits(policy: u64) -> u8 {
    ((policy >> 8) & 0xFF) as u8
}

pub const fn spawn_policy_memory_kb(policy: u64) -> u16 {
    ((policy >> 16) & 0xFFFF) as u16
}

// Spawn flags (msg.regs[3] in PM_SPAWN wire format)
pub const SPAWN_FLAG_USE_PRE_EP: u64 = 1 << 0;
pub const SPAWN_FLAG_RESPAWN: u64 = 1 << 1;
pub const SPAWN_FLAG_START_SUSPENDED: u64 = 1 << 2;

// Deterministic CNode slots for CSpace expansion (root slots 1008-1015)
pub const CSPACE_EXPAND_BASE: u64 = 1008;
pub const MAX_CSPACE_EXPANSIONS: usize = 8;

/// MMAP backing store types.
pub const MMAP_BACKING_NONE: u64 = 0;
pub const MMAP_BACKING_FILE: u64 = 1;
pub const MMAP_BACKING_MOUNT: u64 = 2;
pub const MMAP_BACKING_DEVICE: u64 = 3;
pub const MMAP_BACKING_SHM: u64 = 4;

pub const MMAP_OBJECT_OPT_LAZY: u64 = 1 << 0;
pub const MMAP_OBJECT_OPT_WRITEBACK: u64 = 1 << 1;

/// Per-client bulk SHM size for VFS I/O (1MB = 256 pages).
pub const BULK_SHM_PAGES: u64 = 256;

/// Async operation type codes (used in NET_COMPLETE callbacks).
pub const INET_OP_CONNECT: u8 = 1;
pub const INET_OP_RECV: u8 = 2;
pub const INET_OP_ACCEPT: u8 = 3;
pub const INET_OP_RECVFROM: u8 = 4;
pub const INET_RECV_FLAG_WANT_ADDR: u32 = 1 << 0;
pub const INET_RECV_FLAG_WANT_TIMESTAMP: u32 = 1 << 1;
pub const INET_RECV_FLAG_PEEK: u32 = 1 << 2;
pub const INET_RECV_TIMESTAMP_NONE: u64 = u64::MAX;

/// Runtime network configuration states.
pub const NETCFG_STATE_DOWN: u64 = 0;
pub const NETCFG_STATE_CONFIGURING: u64 = 1;
pub const NETCFG_STATE_READY: u64 = 2;
pub const NETCFG_STATE_FALLBACK: u64 = 3;

/// Extended error codes for network operations.
pub const TRONA_CONN_REFUSED: u64 = 21;
pub const TRONA_TIMED_OUT: u64 = 22;
pub const TRONA_DNS_NXDOMAIN: u64 = 23;
pub const TRONA_DNS_SERVER_FAIL: u64 = 24;
pub const TRONA_PROTO_NOT_SUPPORTED: u64 = 25;
pub const TRONA_HOST_UNREACHABLE: u64 = 26;
pub const TRONA_NET_UNREACHABLE: u64 = 27;
pub const TRONA_NO_BUFS: u64 = 28;
pub const TRONA_CONN_RESET: u64 = 29;
pub const TRONA_NOT_CONNECTED: u64 = 30;
pub const TRONA_IS_CONNECTED: u64 = 31;
pub const TRONA_ADDR_IN_USE: u64 = 32;

pub const MM_SYNC_BACKING_TRUNCATE: u64 = 1 << 0;
