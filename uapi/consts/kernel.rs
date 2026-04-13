// Kernel-level constants: syscalls, invoke labels, errors, object types, flags.
// SPDX-License-Identifier: GPL-2.0-only
//
// These values must be kept in sync with the kernel. The kernel defines
// its own copies in `kernite/src/syscall/mod.rs` and `kernite/src/cap/`.

/// System call numbers.
pub const SYS_SEND: u64 = 0;
pub const SYS_RECV: u64 = 1;
pub const SYS_CALL: u64 = 2;
pub const SYS_REPLY_RECV: u64 = 3;
pub const SYS_NBSEND: u64 = 4;
pub const SYS_SIGNAL: u64 = 5;
pub const SYS_WAIT: u64 = 6;
pub const SYS_POLL: u64 = 7;
pub const SYS_YIELD: u64 = 8;
pub const SYS_INVOKE: u64 = 9;
pub const SYS_DEBUG_PUTCHAR: u64 = 10;
pub const SYS_DEBUG_DUMP_STATE: u64 = 11;
pub const SYS_CLOCK_GETTIME: u64 = 12;
pub const SYS_NANOSLEEP: u64 = 13;
pub const SYS_DEBUG_PUTSTR: u64 = 14;
pub const SYS_DEBUG_PUTBUF: u64 = 15;
pub const SYS_DEBUG_CONSOLE_CONTROL: u64 = 16;
pub const SYS_SET_INVOKE_DEPTHS: u64 = 17;
pub const SYS_FUTEX: u64 = 18;
pub const SYS_GETRANDOM: u64 = 19;
pub const SYS_SHUTDOWN: u64 = 20;
pub const SYS_SEND_TIMED: u64 = 21;
pub const SYS_RECV_TIMED: u64 = 22;
pub const SYS_RECV_ANY: u64 = 23;
pub const SYS_REPLY_RECV_ANY: u64 = 24;
pub const SYS_RECV_ANY_TIMED: u64 = 25;
pub const SYS_REPLY_RECV_ANY_TIMED: u64 = 26;
pub const SYS_NOTIF_RETURN: u64 = 27;
pub const SYS_THREAD_EXIT: u64 = 28;

pub const IPC_RECV_SOURCE_NOTIFICATION: u64 = u64::MAX;

/// Futex operation codes (arg1 of SYS_FUTEX)
pub const FUTEX_WAIT: u64 = 0;
pub const FUTEX_WAKE: u64 = 1;
pub const FUTEX_WAIT_TIMEOUT: u64 = 2;

/// Clock IDs for `SYS_CLOCK_GETTIME`.
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;

/// CNode invoke labels (0x10-0x18).
pub const CNODE_COPY: u64 = 0x10;
pub const CNODE_MINT: u64 = 0x11;
pub const CNODE_MOVE: u64 = 0x12;
pub const CNODE_MUTATE: u64 = 0x13;
pub const CNODE_DELETE: u64 = 0x14;
pub const CNODE_REVOKE: u64 = 0x15;
pub const CNODE_SAVE_CALLER: u64 = 0x16;
pub const CNODE_SET_GUARD: u64 = 0x17;
pub const CNODE_GET_INFO: u64 = 0x18;

/// Untyped invoke labels (0x20-0x21).
pub const UNTYPED_RETYPE: u64 = 0x20;
pub const UNTYPED_RESET: u64 = 0x21;

/// SchedContext invoke labels (0x30-0x31).
pub const SC_CONFIGURE: u64 = 0x30;
pub const SC_BIND: u64 = 0x31;

/// TCB invoke labels (0x40-0x4F).
pub const TCB_CONFIGURE: u64 = 0x40;
pub const TCB_RESUME: u64 = 0x41;
pub const TCB_SUSPEND: u64 = 0x42;
pub const TCB_SET_SPACE: u64 = 0x43;
pub const TCB_WRITE_REGISTERS: u64 = 0x46;
pub const TCB_SET_IPC_BUFFER: u64 = 0x48;
pub const TCB_BIND_NOTIFICATION: u64 = 0x49;
pub const TCB_SET_FAULT_HANDLER: u64 = 0x4B;
pub const TCB_COPY_FPU: u64 = 0x4C;
pub const TCB_SET_TLS_BASE: u64 = 0x4D;
pub const TCB_SET_NOTIFICATION_DISPATCHER: u64 = 0x4E;
pub const TCB_GET_SPACE_INFO: u64 = 0x4F;

/// VSpace invoke labels (0x50-0x5F).
pub const VSPACE_MAP: u64 = 0x50;
pub const VSPACE_UNMAP: u64 = 0x51;
pub const VSPACE_MAP_PT: u64 = 0x52;
pub const VSPACE_WALK: u64 = 0x53;
pub const VSPACE_COPY_PAGE: u64 = 0x54;
pub const VSPACE_MAP_DEVICE: u64 = 0x55;
pub const VSPACE_CLONE_COW_PAGE: u64 = 0x56;
pub const VSPACE_MAP_DEVICE_RANGE: u64 = 0x57;
pub const VSPACE_PROTECT: u64 = 0x58;
pub const VSPACE_MAP_DEMAND: u64 = 0x59;
pub const VSPACE_MAP_DEMAND_RANGE: u64 = 0x5A;
pub const VSPACE_COW_RESOLVE: u64 = 0x5B;
pub const VSPACE_SET_COW_POOL: u64 = 0x5C;
pub const VSPACE_SET_COW_NOTIF: u64 = 0x5D;
pub const VSPACE_REPLENISH_COW_POOL: u64 = 0x5E;
pub const VSPACE_PROTECT_RANGE: u64 = 0x5F;

/// IRQ control/handler invoke labels (0x60-0x64).
pub const IRQ_CONTROL_GET: u64 = 0x60;
pub const IRQ_HANDLER_ACK: u64 = 0x61;
pub const IRQ_HANDLER_SET_NOTIFICATION: u64 = 0x62;
pub const IRQ_HANDLER_CLEAR: u64 = 0x63;
pub const DEVICE_UNTYPED_CREATE: u64 = 0x64;

/// I/O port invoke labels (0x70-0x77).
pub const IOPORT_IN8: u64 = 0x70;
pub const IOPORT_OUT8: u64 = 0x71;
pub const IOPORT_IN16: u64 = 0x72;
pub const IOPORT_OUT16: u64 = 0x73;
pub const IOPORT_IN32: u64 = 0x74;
pub const IOPORT_OUT32: u64 = 0x75;
pub const IOPORT_CONFIGURE: u64 = 0x76;
pub const IOPORT_CREATE: u64 = 0x77;

/// MemoryObject invoke labels (0x90-0x97).
pub const MO_COMMIT: u64 = 0x90;
pub const MO_DECOMMIT: u64 = 0x91;
pub const MO_GET_SIZE: u64 = 0x92;
pub const MO_CLONE: u64 = 0x93;
pub const MO_RESIZE: u64 = 0x94;
pub const MO_READ: u64 = 0x95;
pub const MO_WRITE: u64 = 0x96;
pub const MO_HAS_PAGE: u64 = 0x97;

/// VSpace MemoryObject mapping invoke labels.
pub const VSPACE_MAP_MO: u64 = 0x97;
pub const VSPACE_SHARE_RO_PAGE: u64 = 0x99;
pub const VSPACE_FORK_RANGE: u64 = 0x9A;

/// Error codes returned in `TronaResult.error`.
pub const TRONA_OK: u64 = 0;
pub const TRONA_INVALID_CAPABILITY: u64 = 1;
pub const TRONA_INVALID_OPERATION: u64 = 2;
pub const TRONA_INSUFFICIENT_RIGHTS: u64 = 3;
pub const TRONA_INVALID_ARGUMENT: u64 = 4;
pub const TRONA_OUT_OF_MEMORY: u64 = 5;
pub const TRONA_NOT_FOUND: u64 = 6;
pub const TRONA_BUSY: u64 = 7;
pub const TRONA_ALREADY_EXISTS: u64 = 8;
pub const TRONA_WOULD_BLOCK: u64 = 9;
pub const TRONA_BAD_ADDRESS: u64 = 10;
pub const TRONA_OUT_OF_RANGE: u64 = 11;
pub const TRONA_CANCELLED: u64 = 12;
pub const TRONA_RESTART: u64 = 13;
pub const TRONA_DEADLOCK: u64 = 14;
pub const TRONA_INTERRUPTED: u64 = 15;
pub const TRONA_SLOT_OCCUPIED: u64 = 0x18;
pub const TRONA_ALREADY_MAPPED: u64 = 0x19;
pub const TRONA_ALREADY_BOUND: u64 = 0x1A;
pub const TRONA_IN_PROGRESS: u64 = 0x10;
pub const TRONA_TOO_LARGE: u64 = 0x11;
pub const TRONA_NOT_SUPPORTED: u64 = 0x12;
pub const TRONA_READONLY: u64 = 0x13;
/// Filesystem: component is not a directory (walk through non-dir).
pub const TRONA_NOT_DIRECTORY: u64 = 0x14;
/// Filesystem: target is a directory where a non-directory was expected.
pub const TRONA_IS_DIRECTORY: u64 = 0x15;
/// Filesystem: symbolic link resolution exceeded depth limit.
pub const TRONA_LOOP: u64 = 0x16;
/// Filesystem / device: underlying I/O or backend failure.
pub const TRONA_IO_ERROR: u64 = 0x17;
pub const TRONA_PENDING: u64 = 0x80;

/// VSpace page mapping flags.
pub const VSPACE_FLAG_WRITABLE: u64 = 1 << 0;
pub const VSPACE_FLAG_USER: u64 = 1 << 1;
pub const VSPACE_FLAG_EXECUTABLE: u64 = 1 << 2;
pub const VSPACE_FLAG_CACHE_DISABLE: u64 = 1 << 3;
pub const VSPACE_FLAG_WRITE_THROUGH: u64 = 1 << 4;
pub const VSPACE_FLAG_COW: u64 = 1 << 5;

/// Kernel object types for `UNTYPED_RETYPE`.
pub const OBJ_UNTYPED: u64 = 1;
pub const OBJ_ENDPOINT: u64 = 2;
pub const OBJ_NOTIFICATION: u64 = 3;
pub const OBJ_TCB: u64 = 4;
pub const OBJ_CNODE: u64 = 5;
pub const OBJ_VSPACE: u64 = 6;
pub const OBJ_FRAME: u64 = 7;
pub const OBJ_IRQ_HANDLER: u64 = 8;
pub const OBJ_IO_PORT: u64 = 9;
pub const OBJ_SCHED_CONTEXT: u64 = 10;
pub const OBJ_MEMORY_OBJECT: u64 = 11;

/// Well-known capability slot indices.
pub const CAP_SELF_TCB: u64 = 0;
pub const CAP_SELF_VSPACE: u64 = 1;
pub const CAP_SELF_CSPACE: u64 = 2;

/// Capability rights bitmask (all rights granted).
pub const CAP_RIGHTS_ALL: u64 = 0xFFFF_FFFF;

/// Fixed virtual addresses for well-known memory regions.
pub const INITRD_VADDR: u64 = 0x0000_0000_0100_0000;
pub const SCRATCH_VADDR: u64 = 0x0000_0000_0200_0000;
pub const BOOTINFO_VADDR: u64 = 0x0000_0000_001F_F000;
pub const BOOTINFO_MAGIC: u64 = 0x534C5459_424F4F54; // "SLTYBOOT"

/// Userland CSpace layout auxv types.
pub const AT_TRONA_CSPACE_LAYOUT: u64 = 0x1005;
pub const AT_TRONA_CSPACE_NTFN: u64 = 0x100A;
pub const AT_TRONA_IPC_BUFFER: u64 = 0x100C;
/// SchedContext capability slot for the main thread.
pub const AT_TRONA_SC_CAP: u64 = 0x100E;

/// Single auxv tag carrying the pointer to the child's startup capability
/// table (`TronaCapTableV1`). Every role-bearing cap (procmgr control,
/// vfs/namesrv/mmsrv clients, signal/readiness notifications, initrd/fb
/// untypeds, PCI/COM1 ioports, ...) is delivered exclusively through this
/// single tag — readers walk the table and look up caps by `ROLE_*`
/// identifier. The legacy per-cap `AT_TRONA_*_EP` / `_NTFN` / `_UNTYPED`
/// / `_IOPORT` tags that used to live in the 0x1010..0x101B range have
/// been removed; the child cspace slot numbers they named are now free
/// of any externally-observable ABI.
pub const AT_TRONA_CAP_TABLE: u64 = 0x101C;

/// Magic value at the start of a `TronaCapTableV1`: "SATC" in little-endian.
pub const TRONA_CAP_TABLE_MAGIC: u32 = 0x43544153;

/// Version field of a `TronaCapTableV1` understood by the current readers.
pub const TRONA_CAP_TABLE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Role identifiers for the startup capability table.
//
// Each entry in `TronaCapTableV1.entries[]` carries a `role_id` drawn from
// the ranges below. Spawners (init/procmgr) populate entries; readers look
// them up by role to discover the child-cspace slot where the matching cap
// was placed.
//
// Range      Kind
// 0x0001..   system roles (well-known, shared across all consumers)
// 0x0080..   spawner-internal bridge roles (dual-emit period only)
// 0x0100..   service-local roles (generated per `.service` Require=)
// 0x1000..   reserved for future system roles
// ---------------------------------------------------------------------------

// System roles 0x0001..=0x00FF.
pub const ROLE_PROCMGR_CONTROL: u32 = 0x0001;
pub const ROLE_SERVICE_EP: u32 = 0x0002;
pub const ROLE_NAMESRV_CLIENT: u32 = 0x0003;
pub const ROLE_VFS_CLIENT: u32 = 0x0004;
pub const ROLE_MMSRV_CLIENT: u32 = 0x0005;
pub const ROLE_MMSRV_AUTHORITY_RAW: u32 = 0x0006;
pub const ROLE_RSRCSRV_CLIENT: u32 = 0x0007;
pub const ROLE_RSRCSRV_AUTHORITY_RAW: u32 = 0x0008;
pub const ROLE_CONSOLE_CLIENT: u32 = 0x0009;
pub const ROLE_SIGNAL_NTFN: u32 = 0x000A;
pub const ROLE_READINESS_NTFN: u32 = 0x000B;
pub const ROLE_INITRD_UNTYPED: u32 = 0x000C;
pub const ROLE_FB_UNTYPED: u32 = 0x000D;
pub const ROLE_PCI_IOPORT: u32 = 0x000E;
pub const ROLE_COM1_IOPORT: u32 = 0x000F;
pub const ROLE_WIN32SRV_CLIENT: u32 = 0x0010;
pub const ROLE_CSPACE_NTFN: u32 = 0x0011;
pub const ROLE_SC_CAP: u32 = 0x0012;

// Spawner-internal bridge range 0x0080..=0x00FF — reserved for future
// temporary bridge roles if a new spawner-only intermediate is ever
// needed. The `ROLE_PROCMGR_EXPAND_EP` bridge used during the
// transition away from `AT_TRONA_EXPAND_EP` has been removed — init
// publishes its single expand/RPC slot directly as
// `ROLE_PROCMGR_CONTROL`, and no consumer distinguished the two roles
// while the bridge existed.

// Service-local role range 0x0100..=0x0FFF (generator assigns via djb2).
pub const LOCAL_ROLE_BASE: u32 = 0x0100;
pub const LOCAL_ROLE_END: u32 = 0x0FFF;

// ---------------------------------------------------------------------------
// `TronaCapEntryV1.rights` bits — advisory; the actual kernel rights live in
// the cap itself. Consumers may assert expected bits before invocation.
// ---------------------------------------------------------------------------

pub const CAP_TBL_RIGHT_READ: u32 = 1 << 0;
pub const CAP_TBL_RIGHT_WRITE: u32 = 1 << 1;
pub const CAP_TBL_RIGHT_GRANT: u32 = 1 << 2;
pub const CAP_TBL_RIGHT_INVOKE: u32 = 1 << 3;
pub const CAP_TBL_RIGHT_BADGE: u32 = 1 << 4;
pub const CAP_TBL_RIGHT_DEVICE: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// `TronaCapEntryV1.flags` bits — cap kind / delivery mode hints.
// ---------------------------------------------------------------------------

pub const CAP_TBL_FLAG_BADGED: u32 = 1 << 0;
pub const CAP_TBL_FLAG_RAW: u32 = 1 << 1;
pub const CAP_TBL_FLAG_OPTIONAL: u32 = 1 << 2;
pub const CAP_TBL_FLAG_NOTIFICATION: u32 = 1 << 3;
pub const CAP_TBL_FLAG_UNTYPED: u32 = 1 << 4;
pub const CAP_TBL_FLAG_DEVICE_UT: u32 = 1 << 5;
pub const CAP_TBL_FLAG_IO_PORT: u32 = 1 << 6;

/// PE-specific auxv types (used by ld-trona-pe.so).
pub const AT_SALTYOS_PE_BASE: u64 = 0x2000;
pub const AT_SALTYOS_PE_SIZE: u64 = 0x2001;
pub const AT_SALTYOS_WIN32SRV: u64 = 0x2002;
pub const AT_SALTYOS_KERNEL32_BASE: u64 = 0x2003;
pub const AT_SALTYOS_KERNEL32_SIZE: u64 = 0x2004;

/// ELF format constants.
pub const ELF_PAGE_SIZE: u64 = 4096;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_STRTAB: i64 = 5;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_AARCH64_RELATIVE: u32 = 1027;

/// ELF loader error codes.
pub const ELF_OK: i32 = 0;
pub const ELF_NOT_ELF: i32 = 1;
pub const ELF_NOT_64BIT: i32 = 2;
pub const ELF_NOT_LE: i32 = 3;
pub const ELF_BAD_TYPE: i32 = 4;
pub const ELF_BAD_ARCH: i32 = 5;
pub const ELF_NO_LOAD: i32 = 6;
pub const ELF_RELOC_FAILED: i32 = 7;
pub const ELF_OUT_OF_MEMORY: i32 = 8;
pub const ELF_TOO_SMALL: i32 = 9;
pub const ELF_MAP_FAILED: i32 = 11;

/// PE/COFF format constants.
pub const PE_DOS_MAGIC: u16 = 0x5A4D; // "MZ"
pub const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const PE_OPT_MAGIC_PE32PLUS: u16 = 0x020B;
pub const PE_MACHINE_AMD64: u16 = 0x8664;

/// Subsystem IDs for PersonalityState in procmgr.
pub const SUBSYSTEM_POSIX: u8 = 0;
pub const SUBSYSTEM_WIN32: u8 = 1;
pub const SUBSYSTEM_STARNITE: u8 = 2;
pub const PE_MACHINE_ARM64: u16 = 0xAA64;

/// PE section characteristic flags.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;

/// PE data directory indices.
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/// PE base relocation types (high 4 bits of each reloc entry).
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

/// PE COFF header characteristics.
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// PE loader error codes (offset from ELF range to avoid collision).
pub const PE_OK: i32 = 0;
pub const PE_NOT_PE: i32 = 20;
pub const PE_NOT_64BIT: i32 = 21;
pub const PE_BAD_ARCH: i32 = 22;
pub const PE_NO_SECTIONS: i32 = 23;
pub const PE_RELOC_FAILED: i32 = 24;
pub const PE_OUT_OF_MEMORY: i32 = 25;
pub const PE_TOO_SMALL: i32 = 26;
pub const PE_MAP_FAILED: i32 = 27;
pub const PE_BAD_IMPORT: i32 = 28;

/// PE page size (same as ELF; both use 4K pages on x86_64/aarch64).
pub const PE_PAGE_SIZE: u64 = 4096;

/// CPIO newc header size in bytes.
pub const CPIO_HEADER_SIZE: usize = 110;
