// Core types for SaltyOS userland — kernel ABI, IPC, ELF, CPIO.
// SPDX-License-Identifier: GPL-2.0-only
//
// All types are `#[repr(C)]` for C ABI compatibility with `rtld` and `saltyc`.
// Structures here are shared across the Rust/C boundary and must remain
// layout-stable.

/// Capability slot index. Caps are 64-bit integers that name a slot in the
/// thread's CNode; the kernel resolves the slot to a fat capability object.
pub type Cap = u64;

/// Result of a raw syscall: `error` is 0 on success, otherwise an error code
/// from `consts::TRONA_*`. `value` carries the return payload (e.g. badge,
/// notification bits, clock value).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaResult {
    pub error: u64,
    pub value: u64,
}

/// IPC message buffer passed between userland and the kernel.
///
/// `label` identifies the operation (invoke label or POSIX protocol label).
/// `length` is the number of valid message registers (0..20).
/// `regs[0..3]` travel in CPU registers; `regs[4..19]` overflow via the
/// IPC buffer page.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaMsg {
    pub label: u64,
    pub length: u64,
    pub regs: [u64; 32],
}

impl TronaMsg {
    /// Return a zero-initialized message (label=0, length=0, all regs=0).
    pub const fn zeroed() -> Self {
        TronaMsg {
            label: 0,
            length: 0,
            regs: [0; 32],
        }
    }
}

/// Number of u64 words in the IPC buffer's reserved payload area.
pub const IPC_BUFFER_RESERVED_WORDS: usize = 465;
/// Number of bytes in the IPC buffer's reserved payload area.
pub const IPC_BUFFER_RESERVED_BYTES: usize = IPC_BUFFER_RESERVED_WORDS * core::mem::size_of::<u64>();

/// Kernel-shared IPC buffer page (4096 bytes).
///
/// Mapped at a fixed virtual address per thread. The kernel reads/writes
/// this page during IPC to transfer overflow message registers (MR4+),
/// capability transfer slots, and receive-slot configuration.
///
/// - `msg[0..5]`: mirrors TronaMsg header (label, length, regs[0..3])
/// - `msg[6..33]`: overflow message registers (regs[4..31])
/// - `badge`: sender badge written by kernel on receive
/// - `caps[0..3]`: CNode slots of capabilities to transfer on send
/// - `receive_cnode/index/depth`: destination for received capabilities
/// - `reserved[0..]`: syscall-specific extended payload area.
///   `VSPACE_WALK` writes tuples at word offset 42.
#[repr(C)]
pub struct IpcBuffer {
    pub msg: [u64; 34],
    pub badge: u64,
    pub caps: [u64; 4],
    pub receive_cnode: u64,
    pub receive_index: u64,
    pub receive_depth: u64,
    /// Timeout in nanoseconds for timed IPC operations (SendTimed, etc.).
    /// Written by userland before the syscall; read by the kernel.
    pub timeout_ns: u64,
    pub reserved: [u64; IPC_BUFFER_RESERVED_WORDS],
}

/// Per-thread IPC context: a pointer to the IPC buffer page and the
/// number of capability slots staged for the next send operation.
#[repr(C)]
pub struct IpcContext {
    /// Pointer to the kernel-shared IPC buffer page.
    pub ipc_buffer: *mut IpcBuffer,
    /// Number of caps staged in `ipc_buffer.caps[]` for the next send.
    pub send_cap_count: i32,
}

unsafe impl Sync for IpcContext {}
unsafe impl Send for IpcContext {}

impl IpcContext {
    pub const fn new() -> Self {
        IpcContext {
            ipc_buffer: core::ptr::null_mut(),
            send_cap_count: 0,
        }
    }
}

/// Child CSpace layout contract passed through auxv.
///
/// Producers (init/procmgr) compute the usable slot ranges for the child and
/// place a pointer to this structure in `AT_TRONA_CSPACE_LAYOUT`. Consumers
/// (rtld/CRT/userland) must treat the half-open ranges as the source of truth:
/// `[alloc_base, alloc_limit)`, `[recv_base, recv_limit)`, and
/// `[expand_base, expand_limit)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaCspaceLayoutV1 {
    pub version: u64,
    pub flags: u64,
    pub cnode_bits: u64,
    pub frame_slot_base: u64,
    pub alloc_base: u64,
    pub alloc_limit: u64,
    pub recv_base: u64,
    pub recv_limit: u64,
    pub expand_base: u64,
    pub expand_limit: u64,
}

impl TronaCspaceLayoutV1 {
    pub const VERSION: u64 = 1;
    pub const FLAG_HAS_RECV_RANGE: u64 = 1 << 0;
    pub const FLAG_HAS_EXPAND_RANGE: u64 = 1 << 1;

    pub const fn zeroed() -> Self {
        TronaCspaceLayoutV1 {
            version: 0,
            flags: 0,
            cnode_bits: 0,
            frame_slot_base: 0,
            alloc_base: 0,
            alloc_limit: 0,
            recv_base: 0,
            recv_limit: 0,
            expand_base: 0,
            expand_limit: 0,
        }
    }

    pub const fn alloc_count(&self) -> u64 {
        if self.alloc_limit > self.alloc_base {
            self.alloc_limit - self.alloc_base
        } else {
            0
        }
    }

    pub const fn recv_count(&self) -> u64 {
        if self.recv_limit > self.recv_base {
            self.recv_limit - self.recv_base
        } else {
            0
        }
    }

    pub const fn has_recv_range(&self) -> bool {
        self.recv_limit > self.recv_base
    }

    pub const fn has_expand_range(&self) -> bool {
        self.expand_limit > self.expand_base
    }
}

/// Startup capability table entry — one row per cap delivered to the child.
///
/// `role_id` is drawn from the `ROLE_*` constants in `consts/kernel.rs` and
/// tells the consumer which semantic role this slot fulfils. `slot` is the
/// child-cspace slot number where the spawner has placed the cap. `rights`
/// and `flags` are advisory hints about the cap shape (see `CAP_TBL_RIGHT_*`
/// / `CAP_TBL_FLAG_*`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaCapEntryV1 {
    pub role_id: u32,
    pub slot: u32,
    pub rights: u32,
    pub flags: u32,
}

impl TronaCapEntryV1 {
    pub const fn zeroed() -> Self {
        TronaCapEntryV1 {
            role_id: 0,
            slot: 0,
            rights: 0,
            flags: 0,
        }
    }
}

/// Startup capability table — single point of cap delivery from spawner to
/// child, referenced via `AT_TRONA_CAP_TABLE`.
///
/// Layout: fixed 16-byte header followed by `count` flexible entries. The
/// table is written into a spawner-side scratch page that is mapped into the
/// child's VA; the child reads it once at startup to populate weak symbol
/// slots (for system roles) and per-service `svc_caps::*` slots (for
/// service-local roles).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaCapTableV1 {
    pub magic: u32,
    pub version: u32,
    pub count: u32,
    pub reserved: u32,
    /// Flexible array — real length is `count`. Reached via pointer
    /// arithmetic from the end of this header.
    pub entries: [TronaCapEntryV1; 0],
}

impl TronaCapTableV1 {
    pub const fn zeroed() -> Self {
        TronaCapTableV1 {
            magic: 0,
            version: 0,
            count: 0,
            reserved: 0,
            entries: [],
        }
    }
}

// ---------------------------------------------------------------------------
// `Require=` entry — wire shape for PM_SPAWN requires payload.
// ---------------------------------------------------------------------------

/// Maximum length of a provider service name in a `Require=` entry.
/// Must equal `ini::MAX_SERVICE_NAME` (currently 32).
pub const MAX_REQUIRE_PROVIDER: usize = 32;

/// Maximum length of a service-local alias / system attribute suffix.
pub const MAX_REQUIRE_ALIAS: usize = 24;

/// Maximum number of `Require=` entries per service.
pub const MAX_REQUIRES: usize = 8;

/// `TronaRequireDefV1.kind` — system role recognised by name.
pub const REQUIRE_KIND_SYSTEM: u8 = 0;
/// `TronaRequireDefV1.kind` — service-local role hashed via djb2.
pub const REQUIRE_KIND_LOCAL: u8 = 1;

/// Parsed `Require=` entry in its parser-side shape.
///
/// Used by init's `.service` parser to hold a fully resolved `Require=`
/// entry. The fields cover everything the parser sees: `provider`, `alias`,
/// `kind`, `badged`, `raw`, and the pre-resolved `role_id`.
///
/// This struct is **not** the on-wire shape shipped to procmgr — see
/// `TronaProcmgrRequireV1` (40 B) for that. The wire form drops `alias`
/// because procmgr only ever needs `role_id` (already resolved at parse
/// time) and `provider` (for provider-registry lookup). The build-time
/// `tools/svc_caps_gen.py` generator also reads the parser-side shape —
/// that's why `alias` is kept here.
///
/// Semantics:
///
/// | field          | meaning                                         |
/// |----------------|-------------------------------------------------|
/// | `provider`     | Service name or system short name (NUL-padded). |
/// | `provider_len` | Valid length of `provider`.                     |
/// | `alias`        | System attribute suffix (e.g. `authority_raw`)  |
/// |                | or service-local alias.                          |
/// | `alias_len`    | Valid length of `alias`.                        |
/// | `kind`         | `REQUIRE_KIND_SYSTEM` / `REQUIRE_KIND_LOCAL`.   |
/// | `badged`       | 0/1 — spawner mints a badged copy.              |
/// | `raw`          | 0/1 — privileged raw cap (requires bootstrap    |
/// |                | privilege on the consumer).                      |
/// | `role_id`      | Pre-resolved `ROLE_*` id (system) or djb2 hash  |
/// |                | mod `LOCAL_ROLE_MOD + LOCAL_ROLE_BASE` (local). |
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaRequireDefV1 {
    pub provider: [u8; MAX_REQUIRE_PROVIDER],
    pub provider_len: u8,
    pub alias: [u8; MAX_REQUIRE_ALIAS],
    pub alias_len: u8,
    pub kind: u8,
    pub badged: u8,
    pub raw: u8,
    pub _pad: u8,
    pub role_id: u32,
}

impl TronaRequireDefV1 {
    pub const fn zeroed() -> Self {
        TronaRequireDefV1 {
            provider: [0; MAX_REQUIRE_PROVIDER],
            provider_len: 0,
            alias: [0; MAX_REQUIRE_ALIAS],
            alias_len: 0,
            kind: REQUIRE_KIND_SYSTEM,
            badged: 0,
            raw: 0,
            _pad: 0,
            role_id: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Procmgr service-def registry — wire shape for `PM_REGISTER_SERVICE_DEFS`.
// ---------------------------------------------------------------------------
//
// Init parses every `.service` file in the initrd and resolves each
// `Require=` entry into a `TronaRequireDefV1`. The `alias` field is only
// needed by init's parser and the build-time `svc_caps_gen.py` generator —
// procmgr only ever needs the *resolved* `role_id` plus the `provider`
// service name. We therefore ship a *narrower* shape to procmgr that drops
// `alias`/`alias_len`/`_pad`, shrinking each entry from 68 to 40 bytes.
//
// The whole registry must fit in a single 4 KiB frame so the transfer is
// one IPC call with one cap. With `MAX_PROCMGR_REQUIRES = 6`:
//
//   header                  16 bytes
//   per-service def        276 bytes  (36 fixed + 6 * 40)
//   capacity (4096 - 16) / 276 = 14 entries
//
// Post-procmgr services in the current image: 12. Two slots of headroom.

/// Maximum number of `Require=` entries shipped to procmgr per service.
///
/// Smaller than `MAX_REQUIRES` (8) on purpose: the parser-side shape lives
/// in init's stack frames where 8 is comfortable, but the registry shipped
/// to procmgr must fit alongside ~12 service defs in one frame. Init must
/// reject any post-procmgr service with more than this many `Require=`
/// entries at serialization time.
pub const MAX_PROCMGR_REQUIRES: usize = 6;

/// Maximum number of service defs procmgr accepts in its registry.
///
/// Sized so that `header + MAX_PROCMGR_SERVICE_DEFS * sizeof(def)` fits in
/// one 4 KiB frame: `16 + 14 * 276 = 3880 ≤ 4096`.
pub const MAX_PROCMGR_SERVICE_DEFS: usize = 14;

/// Magic for `TronaProcmgrServiceDefsV1`. Distinct from
/// `TRONA_CAP_TABLE_MAGIC` so a malformed transfer cannot be misread as a
/// cap table. Bytes spell `"PMSD"` little-endian.
pub const TRONA_PROCMGR_DEFS_MAGIC: u32 = 0x44534D50;

/// Wire version for `TronaProcmgrServiceDefsV1`. Bumped on incompatible
/// layout changes (field add/remove/reorder). Procmgr rejects mismatches.
pub const TRONA_PROCMGR_DEFS_VERSION: u32 = 1;

/// One `Require=` entry as procmgr sees it.
///
/// Narrower than `TronaRequireDefV1`: the `alias` field is dropped because
/// procmgr never needs it — `role_id` is pre-resolved by init, and provider
/// lookup uses `provider` only. Layout is `#[repr(C)]` and naturally 4-byte
/// aligned.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaProcmgrRequireV1 {
    pub provider: [u8; MAX_REQUIRE_PROVIDER],
    pub provider_len: u8,
    pub kind: u8,
    pub badged: u8,
    pub raw: u8,
    pub role_id: u32,
}

impl TronaProcmgrRequireV1 {
    pub const fn zeroed() -> Self {
        TronaProcmgrRequireV1 {
            provider: [0; MAX_REQUIRE_PROVIDER],
            provider_len: 0,
            kind: REQUIRE_KIND_SYSTEM,
            badged: 0,
            raw: 0,
            role_id: 0,
        }
    }
}

/// One service def as procmgr sees it.
///
/// `name` is the service name (also used as the spawn binary key by
/// procmgr's provider registry). `bootstrap_privileged` gates
/// `*_AUTHORITY_RAW` roles. `requires[..require_count]` is the resolved cap
/// requirement list.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaProcmgrServiceDefV1 {
    pub name: [u8; MAX_REQUIRE_PROVIDER],
    pub name_len: u8,
    pub bootstrap_privileged: u8,
    pub require_count: u8,
    pub _pad: u8,
    pub requires: [TronaProcmgrRequireV1; MAX_PROCMGR_REQUIRES],
}

impl TronaProcmgrServiceDefV1 {
    pub const fn zeroed() -> Self {
        TronaProcmgrServiceDefV1 {
            name: [0; MAX_REQUIRE_PROVIDER],
            name_len: 0,
            bootstrap_privileged: 0,
            require_count: 0,
            _pad: 0,
            requires: [TronaProcmgrRequireV1::zeroed(); MAX_PROCMGR_REQUIRES],
        }
    }
}

/// Top-level header for the procmgr service-def registry.
///
/// Layout: 16-byte header followed by `count` `TronaProcmgrServiceDefV1`
/// entries (flexible array). Init writes this into a single frame, maps it
/// at a scratch VA, and transfers the frame cap to procmgr via
/// `PM_REGISTER_SERVICE_DEFS`. Procmgr maps the frame at its own scratch
/// VA, validates `magic` + `version`, copies the entries into a static
/// array, then unmaps and acks.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaProcmgrServiceDefsV1 {
    pub magic: u32,
    pub version: u32,
    pub count: u32,
    pub reserved: u32,
    /// Flexible array — real length is `count`, capped at
    /// `MAX_PROCMGR_SERVICE_DEFS`. Reached via pointer arithmetic from the
    /// end of this header.
    pub entries: [TronaProcmgrServiceDefV1; 0],
}

impl TronaProcmgrServiceDefsV1 {
    pub const fn zeroed() -> Self {
        TronaProcmgrServiceDefsV1 {
            magic: 0,
            version: 0,
            count: 0,
            reserved: 0,
            entries: [],
        }
    }
}

/// ELF64 file header. Matches the System V ABI ELF specification.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// ELF64 program header. Describes a segment (PT_LOAD, PT_INTERP, etc.).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// ELF64 dynamic section entry (tag + value pair from PT_DYNAMIC).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

/// ELF64 relocation entry with explicit addend (used for R_X86_64_RELATIVE).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

/// Result of loading an ELF binary: entry point, load base address, and
/// the end of the loaded BSS (program break).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfLoadResult {
    pub entry: u64,
    pub base: u64,
    pub brk: u64,
}

/// Tracks a single mapped page during ELF loading: its virtual address,
/// the frame capability slot, and VSpace mapping flags.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfPageEntry {
    pub vaddr: u64,
    pub frame_cap: Cap,
    pub flags: u64,
}

/// Context for the userspace ELF loader.
///
/// The loader uses a "scratch-map" strategy: each page is temporarily mapped
/// into the loader's own VSpace at `scratch_vaddr` for writing, then unmapped
/// and remapped into the child's VSpace. This allows loading into a foreign
/// address space without switching page tables.
#[repr(C)]
pub struct ElfLoaderCtx {
    /// Untyped cap to retype frames from (0 = skip internal retype).
    pub untyped: Cap,
    /// Loader's own VSpace cap (for scratch mapping).
    pub self_vspace: Cap,
    /// Target child's VSpace cap.
    pub child_vspace: Cap,
    /// Virtual address in the loader's VSpace used as a scratch page.
    pub scratch_vaddr: u64,
    /// Next CNode slot to use for frame allocation (bump allocator).
    pub next_frame_slot: Cap,
    /// Optional callback to allocate a frame slot (overrides bump allocator).
    pub alloc_frame_slot: Option<unsafe extern "C" fn(*mut u8) -> Cap>,
    /// Opaque pointer passed to `alloc_frame_slot`.
    pub alloc_opaque: *mut u8,
    /// Optional callback to record each (vaddr, frame_cap, flags) mapping.
    pub record_page: Option<unsafe extern "C" fn(*mut u8, u64, Cap, u64) -> i32>,
    /// Opaque pointer passed to `record_page`.
    pub record_opaque: *mut u8,
}

/// CPIO archive entry (basic): name pointer/length and data pointer/length.
/// Returned by `cpio_find_file` and `cpio_next`. Pointers reference data
/// within the mapped archive (no copies).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpioEntry {
    pub name: *const u8,
    pub name_len: usize,
    pub data: *const u8,
    pub data_len: usize,
}

impl CpioEntry {
    pub const fn zeroed() -> Self {
        CpioEntry {
            name: core::ptr::null(),
            name_len: 0,
            data: core::ptr::null(),
            data_len: 0,
        }
    }
}

/// Extended CPIO archive entry: includes inode, mode, uid, gid, nlink, and
/// mtime parsed from the CPIO newc header fields. Used by VFS to populate
/// directory entries with proper metadata.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpioEntryExt {
    pub name: *const u8,
    pub name_len: usize,
    pub data: *const u8,
    pub data_len: usize,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub ino: u32,
}

impl CpioEntryExt {
    pub const fn zeroed() -> Self {
        CpioEntryExt {
            name: core::ptr::null(),
            name_len: 0,
            data: core::ptr::null(),
            data_len: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            mtime: 0,
            ino: 0,
        }
    }
}

/// POSIX timespec: seconds + nanoseconds (used by clock_gettime, nanosleep).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec {
    pub tv_sec: u64,
    pub tv_nsec: u64,
}

impl Timespec {
    pub const fn zeroed() -> Self {
        Timespec { tv_sec: 0, tv_nsec: 0 }
    }
}

/// POSIX timeval: seconds + microseconds (used by gettimeofday).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    pub tv_sec: u64,
    pub tv_usec: u64,
}

impl Timeval {
    pub const fn zeroed() -> Self {
        Timeval { tv_sec: 0, tv_usec: 0 }
    }
}

// ---------------------------------------------------------------------------
// TLS metadata types (shared between substrate globals and posix::tls)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TLS block types (shared between substrate and personality layers)
// ---------------------------------------------------------------------------

/// Cleanup handler node for pthread_cleanup_push/pop.
#[repr(C)]
pub struct CleanupHandler {
    pub routine: unsafe extern "C" fn(*mut u8),
    pub arg: *mut u8,
    pub next: *mut CleanupHandler,
}

unsafe impl Send for CleanupHandler {}
unsafe impl Sync for CleanupHandler {}

/// Per-thread local storage block.
///
/// Layout is `#[repr(C)]` for ABI stability. The `self_ptr` field MUST be
/// first — the x86_64 TLS ABI mandates that `%fs:0` dereferences to the
/// TLS block's own address.
///
/// This struct is the canonical ABI type shared by substrate, POSIX, Win32,
/// and any future personality. Substrate sets `self_ptr`, `ipc_ctx`,
/// `thread_id`. POSIX adds `errno`, `cancel_*`, `cleanup_stack`.
/// The `desc` field is an opaque back-pointer to the substrate `ThreadDesc`;
/// personalities cast through it to reach personality-specific extensions.
#[repr(C)]
pub struct ThreadLocalBlock {
    /// Self-pointer: `%fs:0 == &self` (x86_64 TLS ABI requirement)
    pub self_ptr: *mut ThreadLocalBlock,
    /// Per-thread IPC context (IPC buffer pointer + send-cap count)
    pub ipc_ctx: IpcContext,
    /// Thread ID (unique per thread within a process)
    pub thread_id: u64,
    /// Per-thread errno value
    pub errno: i32,
    /// Padding for alignment
    pub _pad0: i32,
    /// Back-pointer to substrate ThreadDesc (opaque — cast in substrate only)
    pub desc: *mut u8,
    /// Cancellation state: 0=ENABLE, 1=DISABLE
    pub cancel_state: u32,
    /// Cancellation type: 0=DEFERRED (only type supported)
    pub cancel_type: u32,
    /// Set to 1 when cancellation has been requested
    pub cancel_pending: u32,
    pub _pad1: u32,
    /// LIFO stack of cleanup handlers (intrusive linked list)
    pub cleanup_stack: *mut CleanupHandler,
    /// Futex address the thread is currently blocked on (for cancel wake).
    /// Set before futex_wait at cancellation points, cleared after return.
    /// 0 means the thread is not blocked on any cancellation-point futex.
    pub blocked_futex_addr: core::sync::atomic::AtomicU64,

    // ----- basaltc per-thread state (appended to preserve existing offsets) -----

    /// Per-thread strtok() save pointer (used by basaltc strtok).
    pub strtok_save: *mut u8,
    /// Per-thread `struct tm` buffer for gmtime()/localtime() (56 bytes).
    pub libc_tm_buf: [u8; 56],
    /// Per-thread asctime() buffer (64 bytes).
    pub libc_asctime_buf: [u8; 64],
    /// Per-thread ctime() buffer (64 bytes).
    pub libc_ctime_buf: [u8; 64],
}

unsafe impl Send for ThreadLocalBlock {}
unsafe impl Sync for ThreadLocalBlock {}

impl ThreadLocalBlock {
    /// Create a zero-initialized TLS block with self_ptr set to null.
    /// The caller must set `self_ptr = &mut self as *mut _` after placement.
    pub const fn zeroed() -> Self {
        ThreadLocalBlock {
            self_ptr: core::ptr::null_mut(),
            ipc_ctx: IpcContext::new(),
            thread_id: 0,
            errno: 0,
            _pad0: 0,
            desc: core::ptr::null_mut(),
            cancel_state: 0,
            cancel_type: 0,
            cancel_pending: 0,
            _pad1: 0,
            cleanup_stack: core::ptr::null_mut(),
            blocked_futex_addr: core::sync::atomic::AtomicU64::new(0),
            strtok_save: core::ptr::null_mut(),
            libc_tm_buf: [0; 56],
            libc_asctime_buf: [0; 64],
            libc_ctime_buf: [0; 64],
        }
    }
}

/// aarch64 ABI thread pointer block.
/// `TPIDR_EL0` points to this structure. `runtime_tcb` points to the
/// `ThreadLocalBlock` that follows the ELF TLS data region.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct AbiThreadPointerBlock {
    pub runtime_tcb: *mut ThreadLocalBlock,
    pub reserved: u64,
}

#[cfg(target_arch = "aarch64")]
unsafe impl Send for AbiThreadPointerBlock {}
#[cfg(target_arch = "aarch64")]
unsafe impl Sync for AbiThreadPointerBlock {}

#[cfg(target_arch = "aarch64")]
impl AbiThreadPointerBlock {
    pub const fn zeroed() -> Self {
        AbiThreadPointerBlock {
            runtime_tcb: core::ptr::null_mut(),
            reserved: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TLS metadata types (shared between substrate globals and tls layer)
// ---------------------------------------------------------------------------

/// Maximum number of static TLS modules exported by rtld.
pub const MAX_STATIC_TLS_MODULES: usize = 8;

/// Per-module static TLS metadata exported by rtld.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct StaticTlsModule {
    pub module_id: u64,
    pub template_addr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub tp_offset: i64,
}

impl StaticTlsModule {
    pub const fn zeroed() -> Self {
        StaticTlsModule {
            module_id: 0,
            template_addr: 0,
            filesz: 0,
            memsz: 0,
            tp_offset: 0,
        }
    }
}
