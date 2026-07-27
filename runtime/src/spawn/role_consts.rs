// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyOS startup capability-table layout — role IDs, magic, hashing.
//!
//! The SaltyOS startup block (`SaltyOSStartupLayoutV1`) carries a
//! `SaltyOSCapTableV1` pointer; spawners (init) populate one entry per
//! delivered cap, each tagged with a `role_id` drawn from the ranges
//! below. Consumers resolve a role to a child-cspace slot by walking
//! the table.
//!
//! ```text
//! Range      Kind
//! 0x0001..   system roles (well-known, shared across all consumers)
//! 0x0080..   reserved for spawner-internal bridge roles
//! 0x0100..   service-local roles (generated per-`.service` Require=)
//! 0x1000..   reserved for future system roles
//! ```
//!
//! ## Role categories
//!
//! ### Bootstrap (delivered via cap_table at every spawn)
//!   `ROLE_INIT_CONTROL`, `ROLE_NAMESRV_CLIENT` (= namespace root),
//!   `ROLE_SIGNAL_PIPE`,
//!   `ROLE_SERVICE_EP` / `ROLE_SERVICE_CLIENT_EP`, plus the always-on
//!   system caps `ROLE_KERNEL_RNG / ROLE_CLOCK / ROLE_SYSTEM_INFO`.
//!
//! ### Privileged (manifest `FLAG_PRIVILEGED` gate)
//!   `ROLE_SYSTEM_CONTROL`, `ROLE_KERNEL_DEBUG` — privileged subset of
//!   system caps, only delivered to services flagged privileged.
//!
//! ### Manifest-policy (spawn-time grant per service manifest)
//!   `ROLE_INITRD_UNTYPED`, `ROLE_FB_UNTYPED`, `ROLE_PCI_IOPORT`,
//!   `ROLE_COM1_IOPORT / _IRQ / _NTFN`, `ROLE_KBD_IOPORT / _IRQ`,
//!   `ROLE_DEVICE_CONTROL`. Hardware/raw-untyped caps that namesrv does
//!   not vend; init grants per `ServiceDef::policy_caps`.
//!
//! ### Bootstrap / early loader
//!   `ROLE_MMSRV_CLIENT` is delivered at spawn time because dynamic
//!   loaders may need `MM_MPROTECT` before the normal runtime slot
//!   allocator can perform namesrv lazy resolution.
//!
//! ### Lazy (resolved by child via `NAMESRV_LOOKUP` on first use)
//!   `ROLE_RSRCSRV_CLIENT`, `ROLE_VFS_CLIENT`, `ROLE_CONSOLE_CLIENT`,
//!   `ROLE_WIN32SRV_CLIENT`, plus service-local `Requires=*` consumer
//!   caps.
//!
//! ### Log sink (spawn-time when `logsrv` is ready)
//!   `ROLE_LOG_CLIENT` — non-privileged userland diagnostics. This is
//!   intentionally distinct from `ROLE_KERNEL_DEBUG`.
//!
//! ### Boot plumbing (spawner → single core server, no public lookup)
//!   `ROLE_NAMESRV_MASTER_EQ / _MASTER_MP / _WATCH_BASE / _PARK_TIMER /
//!   _PARK_SLOT_BASE`, `ROLE_MMSRV_SERVICE_EQ / _FAULT_EQ / _FAULT_TCB /
//!   _FAULT_SC / _FAULT_MP_MASTER_RECV / _FAULT_STACK_FRAME`,
//!   `ROLE_NAMESRV_PUBLISHER`, `ROLE_*_AUTHORITY_RAW`. `system_role_target`
//!   deliberately omits these
//!   — they are spawner-private and do not have public weak-symbol
//!   hookup.

/// Magic value at the start of a `SaltyOSCapTableV1`: "SATC" little-endian.
pub const SALTYOS_CAP_TABLE_MAGIC: u32 = 0x43544153;

/// Version field of a `SaltyOSCapTableV1` understood by current readers.
pub const SALTYOS_CAP_TABLE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// System roles 0x0001..=0x00FF.
// ---------------------------------------------------------------------------

pub const ROLE_INIT_CONTROL: u32 = 0x0001;
pub const ROLE_SERVICE_EP: u32 = 0x0002;
pub const ROLE_NAMESRV_CLIENT: u32 = 0x0003;
pub const ROLE_VFS_CLIENT: u32 = 0x0004;
pub const ROLE_MMSRV_CLIENT: u32 = 0x0005;
pub const ROLE_MMSRV_AUTHORITY_RAW: u32 = 0x0006;
pub const ROLE_RSRCSRV_CLIENT: u32 = 0x0007;
pub const ROLE_RSRCSRV_AUTHORITY_RAW: u32 = 0x0008;
pub const ROLE_CONSOLE_CLIENT: u32 = 0x0009;
pub const ROLE_SIGNAL_PIPE: u32 = 0x000A;
/// Peer endpoint to `ROLE_SERVICE_EP`. Services publish this cap to
/// namesrv and use it for self-injected wake messages; clients write
/// through this side, while the service reactor reads `ROLE_SERVICE_EP`.
pub const ROLE_SERVICE_CLIENT_EP: u32 = 0x000B;
pub const ROLE_INITRD_UNTYPED: u32 = 0x000C;
pub const ROLE_FB_UNTYPED: u32 = 0x000D;
pub const ROLE_PCI_IOPORT: u32 = 0x000E;
pub const ROLE_COM1_IOPORT: u32 = 0x000F;
pub const ROLE_WIN32SRV_CLIENT: u32 = 0x0010;
pub const ROLE_CSPACE_NTFN: u32 = 0x0011;
pub const ROLE_SC_CAP: u32 = 0x0012;
pub const ROLE_COM1_IRQ: u32 = 0x0013;
pub const ROLE_COM1_NTFN: u32 = 0x0014;
pub const ROLE_KBD_IOPORT: u32 = 0x0015;
pub const ROLE_KBD_IRQ: u32 = 0x0016;
pub const ROLE_DEVICE_CONTROL: u32 = 0x0017;
pub const ROLE_LOG_CLIENT: u32 = 0x0018;

// JIT exec-authority — an `ExecAuthority` cap delivered to JIT-permitted
// processes so they may confer `EXECUTE` on their own MemoryObjects via
// `mo_mark_executable`. Ordinary processes never receive it.
pub const ROLE_JIT_EXEC_AUTHORITY: u32 = 0x0019;

// System capability roles — `KernelRng` / `Clock` / `SystemControl` /
// `SystemInfo` / `KernelDebug` are the per-process system cap set
// introduced by the new ABI. Spawners with the matching authority
// hand a delegated copy to each child.
pub const ROLE_KERNEL_RNG: u32 = 0x001D;
pub const ROLE_CLOCK: u32 = 0x001E;
pub const ROLE_SYSTEM_CONTROL: u32 = 0x001F;
pub const ROLE_SYSTEM_INFO: u32 = 0x0020;
pub const ROLE_KERNEL_DEBUG: u32 = 0x0021;

// Code-loading authority client — the `ldsrv` service endpoint every
// process resolves `DT_NEEDED` libraries through (and, after the caller's
// own VFS exec-permission check, main images). Child-distributed like the
// other `*_CLIENT` roles.
pub const ROLE_LDSRV_CLIENT: u32 = 0x0022;

// Namesrv-private boot roles. Init retypes namesrv's startup objects
// directly (namesrv has no rsrcsrv at boot) and delivers them via the
// cap table; namesrv looks them up by role id, no public weak-symbol
// hookup. `system_role_target` deliberately omits these.
pub const ROLE_NAMESRV_PUBLISHER: u32 = 0x0023;
pub const ROLE_NAMESRV_MASTER_EQ: u32 = 0x0024;
pub const ROLE_NAMESRV_MASTER_MP: u32 = 0x0025;
pub const ROLE_NAMESRV_WATCH_BASE: u32 = 0x0026;
pub const ROLE_NAMESRV_PARK_TIMER: u32 = 0x0027;

// Mmsrv-private boot roles. Init pre-allocates these objects when
// spawning mmsrv so the second TCB (fault dispatcher) and its EQs are
// ready before mmsrv's main reactor enters its loop. Like the namesrv
// roles above, these are intentionally absent from
// `system_role_target` — they are spawner-private.
pub const ROLE_MMSRV_SERVICE_EQ: u32 = 0x0029;
pub const ROLE_MMSRV_FAULT_EQ: u32 = 0x002A;
pub const ROLE_MMSRV_FAULT_TCB: u32 = 0x002B;
pub const ROLE_MMSRV_FAULT_SC: u32 = 0x002C;
pub const ROLE_MMSRV_FAULT_MP_MASTER_RECV: u32 = 0x002D;
pub const ROLE_MMSRV_FAULT_STACK_FRAME: u32 = 0x002E;

// `ROLE_NAMESRV_BOOT_UNTYPED` — spawner-private untyped delivered to
// namesrv at boot. namesrv's `SegmentAllocator` retypes pages out of
// it for `EventLoop` cookie-table backing because boot
// order puts namesrv ahead of mmsrv (so `mm::mmap_anon` isn't
// available) and rsrcsrv's vending object set excludes `OBJ_FRAME`.
pub const ROLE_NAMESRV_BOOT_UNTYPED: u32 = 0x002F;

// rsrcsrv's `EventLoop` plumbing. Init retypes the
// `EventQueue` from rsrcsrv's plumbing untyped (the same pool that
// backs rsrcsrv's TCB / VSpace / CNode / SC / IPC frame / stack);
// rsrcsrv's `read_startup_caps` looks it up by role. The
// master-MP `Watch` itself is retyped by rsrcsrv at startup from
// `ROLE_RSRCSRV_AUTHORITY_RAW` (rsrcsrv's vending object set
// includes `OBJ_WATCH`). Spawner-private — absent from
// `system_role_target`.
pub const ROLE_RSRCSRV_SERVICE_EQ: u32 = 0x0030;

// ldsrv-private boot role. The recv end of the private adopt MP init
// installs into ldsrv's cspace (init keeps the send end); over it PID 1
// transfers the boot code-MO set and moves the exec-authority cap, so no
// public client can forge an adoption or steal the authority. Spawner-
// private — absent from `system_role_target`, like the boot roles above.
pub const ROLE_LDSRV_ADOPT_RECV: u32 = 0x0031;

// ldsrv-private boot role. The recv end of init's *dedicated exec-control* MP —
// a separate channel from the adopt MP (which is boot-only and sealed). Over it
// init issues steady-state `resolve_main` requests for program main images; only
// init holds the send end, so the conferral of EXECUTE on a caller-supplied
// backing is gated to the trusted execve broker. Spawner-private.
pub const ROLE_LDSRV_EXEC_CONTROL_RECV: u32 = 0x0032;

// ldsrv-private boot role. A small plumbing untyped init carves for ldsrv at
// spawn, from which ldsrv retypes its reactor objects (one EventQueue + the
// per-EP Watches) so it can serve the public resolve EP and the private
// exec-control MP concurrently. Spawner-private.
pub const ROLE_LDSRV_PLUMBING_UNTYPED: u32 = 0x0033;

// ---------------------------------------------------------------------------
// Service-local role range 0x0100..=0x0FFF.
//
// init's parser hashes a `"<provider>:<alias>"` key into this bucket
// via `local_role_id`. Every producer and consumer must use the
// helper rather than open-coding the formula.
// ---------------------------------------------------------------------------

pub const LOCAL_ROLE_BASE: u32 = 0x0100;
pub const LOCAL_ROLE_END: u32 = 0x0FFF;

/// Size of the service-local role bucket used when reducing a djb2
/// hash into `[LOCAL_ROLE_BASE, LOCAL_ROLE_END]`.
pub const LOCAL_ROLE_MOD: u32 = 0x0F00;

/// djb2 string hash. Deterministic and endian-independent.
pub const fn djb2_hash(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        hash = hash.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

/// Reduce a `"<provider>:<alias>"` key into the service-local role
/// bucket. Every spawner and generator that needs a local role id
/// must go through this helper — never open-code the formula.
pub const fn local_role_id(key: &[u8]) -> u32 {
    LOCAL_ROLE_BASE + (djb2_hash(key) % LOCAL_ROLE_MOD)
}

// ---------------------------------------------------------------------------
// `SaltyOSCapEntryV1.rights` bits — advisory; the actual kernel rights
// live in the cap itself. Consumers may assert expected bits before
// invocation.
// ---------------------------------------------------------------------------

pub const CAP_TBL_RIGHT_READ: u32 = 1 << 0;
pub const CAP_TBL_RIGHT_WRITE: u32 = 1 << 1;
pub const CAP_TBL_RIGHT_GRANT: u32 = 1 << 2;
pub const CAP_TBL_RIGHT_INVOKE: u32 = 1 << 3;
pub const CAP_TBL_RIGHT_BADGE: u32 = 1 << 4;
pub const CAP_TBL_RIGHT_DEVICE: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// `SaltyOSCapEntryV1.flags` bits — cap kind / delivery mode hints.
// ---------------------------------------------------------------------------

pub const CAP_TBL_FLAG_BADGED: u32 = 1 << 0;
pub const CAP_TBL_FLAG_RAW: u32 = 1 << 1;
pub const CAP_TBL_FLAG_OPTIONAL: u32 = 1 << 2;
pub const CAP_TBL_FLAG_NOTIFICATION: u32 = 1 << 3;
pub const CAP_TBL_FLAG_UNTYPED: u32 = 1 << 4;
pub const CAP_TBL_FLAG_DEVICE_UT: u32 = 1 << 5;
pub const CAP_TBL_FLAG_IO_PORT: u32 = 1 << 6;
/// Role entry reserves a child CSpace slot but does not currently hold a cap.
/// Runtime well-known getters must not install these entries as live caps.
pub const CAP_TBL_FLAG_RESERVED: u32 = 1 << 7;
