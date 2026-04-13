// Resource server (rsrcsrv) IPC protocol labels (0xE0-0xE6 range).
// SPDX-License-Identifier: GPL-2.0-only
//
// rsrcsrv is the sole runtime authority for kernel object allocation, quota
// accounting, and owner-based reclaim.

/// Allocate a single kernel object.
/// Request: MR0=owner_id, MR1=obj_type, MR2=size_bits, MR3=flags
/// Reply:   cap[0]=object cap, MR0=handle (u64), MR1=status
pub const RES_ALLOC_OBJECT: u64 = 0xE0;

/// Allocate a heterogeneous batch of kernel objects in one IPC.
/// Request: MR0=owner_id, MR1=count, MR2..=packed (obj_type<<8 | size_bits) per slot.
///          Up to 8 entries via MRs; larger batches use the IPC buffer.
/// Reply:   caps[0..count]=object caps, MR0..=handles[0..count], MRn=status
pub const RES_ALLOC_BATCH: u64 = 0xE1;

/// Free a single handle previously returned by RES_ALLOC_OBJECT/RES_ALLOC_BATCH.
/// rsrcsrv revokes the back-reference cap (which invalidates all derived caps
/// including the caller's copy) and decrements quota usage.
/// Request: MR0=owner_id, MR1=handle
/// Reply:   MR0=status
pub const RES_FREE_HANDLE: u64 = 0xE2;

/// Reclaim every handle currently owned by owner_id. Used on process exit.
/// Request: MR0=owner_id
/// Reply:   MR0=status, MR1=freed_count
pub const RES_RECLAIM_OWNER: u64 = 0xE3;

/// Query current usage stats for an owner.
/// Request: MR0=owner_id
/// Reply:   MR0=status, MR1=bytes_in_use, MR2=handle_count
pub const RES_QUERY_USAGE: u64 = 0xE4;

/// Set or update quota limits for an owner. Setting both to 0 means unlimited.
/// The high bit of MR2 (RES_QUOTA_FLAG_PROMOTE_PRIVILEGED) is reserved for
/// init to promote a target owner_id (typically procmgr) to the privileged
/// caller set, allowing it to allocate on behalf of other owners.
/// Request: MR0=owner_id, MR1=max_bytes, MR2=max_handles | flags
/// Reply:   MR0=status
pub const RES_SET_QUOTA: u64 = 0xE5;

/// Hand an untyped capability to rsrcsrv's pool. Used by init during boot to
/// transfer all root untypeds to rsrcsrv after spawning it.
/// Request: cap[0]=untyped (transferred)
/// Reply:   MR0=status
pub const RES_ADOPT_UNTYPED: u64 = 0xE6;

/// Promote target owner to privileged set. High bit of RES_SET_QUOTA's MR2.
/// Only accepted when caller is init (verified via caller badge).
pub const RES_QUOTA_FLAG_PROMOTE_PRIVILEGED: u64 = 1 << 63;
