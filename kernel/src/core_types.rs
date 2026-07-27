// SPDX-License-Identifier: GPL-2.0-only
//
//! Core trona-userland types — kernel ABI return shape, IPC context,
//! startup contract, runtime install, cap table, service-def registry,
//! TLS layout, loader (rtld) handoff.
//!
//! All types here are `#[repr(C)]` for ABI stability across the
//! Rust/C boundary. The kernel-side IPC buffer (4096 bytes) is the
//! bindgen output `uapi::kernite_ipc_buffer` — never define a second
//! copy of that struct here, and never re-introduce a PascalCase
//! `IpcBuffer` alias for it.

// ---------------------------------------------------------------------------
// Capability handle.
// ---------------------------------------------------------------------------

/// Capability slot index. Caps are 64-bit integers naming a slot in
/// the thread's CNode; the kernel resolves the slot to a fat
/// capability object on dispatch.
pub type Cap = u64;
/// A borrowed, non-owning reference to a capability: its slot address
/// plus the CSpace invoke depth needed to resolve it.
///
/// `CapRef` is `Copy` — handing one around or storing it never transfers
/// ownership and never releases the slot. It is the argument type for
/// capability *invocations* (which read a cap without consuming it) and
/// the representation for caps the holder must never release: well-known
/// slots (`CAP_SELF_*`), cap-table entries, untyped authorities, and
/// process-lifetime role caps (see [`crate`] consumers' `LeakedCapRef`).
///
/// Owning handles (`OwnedSlot` / `OwnedCap`, defined in `trona_runtime`
/// where the slot allocator lives) borrow as a `CapRef` for invocation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CapRef {
    addr: Cap,
    depth: u8,
}

impl CapRef {
    /// The null reference (slot 0, depth 0). Treated as "absent".
    pub const NULL: Self = Self { addr: 0, depth: 0 };

    /// A reference to a flat root-CNode slot (invoke depth 0).
    pub const fn flat(addr: Cap) -> Self {
        Self { addr, depth: 0 }
    }

    /// A reference carrying an explicit CSpace invoke depth (for slots
    /// inside an expansion sub-CNode).
    pub const fn at_depth(addr: Cap, depth: u8) -> Self {
        Self { addr, depth }
    }

    /// The raw slot address, for staging into the IPC buffer / syscall
    /// argument registers (the ABI boundary is `Cap` = `u64`).
    pub const fn addr(&self) -> Cap {
        self.addr
    }

    /// The CSpace invoke depth required to resolve this slot.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    pub const fn is_null(&self) -> bool {
        self.addr == 0
    }
}

impl From<Cap> for CapRef {
    /// A bare slot address with no recorded depth resolves as a flat
    /// root-CNode slot.
    fn from(addr: Cap) -> Self {
        Self::flat(addr)
    }
}

impl Default for CapRef {
    /// The default capability reference is [`CapRef::NULL`] — an absent
    /// cap at the root depth. This is what an optional owned handle
    /// collapses to when it is missing (`opt.map(OwnedCap::borrow)`
    /// borrows a present cap and falls back to a null borrow otherwise),
    /// so a `None` reaches an invocation as a harmless null slot rather
    /// than a stale address.
    fn default() -> Self {
        Self::NULL
    }
}

/// A process-lifetime capability acquired dynamically — a role / well-known
/// cap delivered through the startup cap table or resolved lazily via the
/// name service, intentionally never released (its owner is the process
/// itself, for the whole run). Distinct from a borrowed [`CapRef`] only to
/// document that no scope frees it. `Copy`, no drop behaviour; converts to a
/// `CapRef` for invocation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LeakedCapRef(CapRef);

impl LeakedCapRef {
    pub const NULL: Self = Self(CapRef::NULL);

    /// A leaked reference to a flat root-CNode slot.
    pub const fn flat(addr: Cap) -> Self {
        Self(CapRef::flat(addr))
    }

    /// A leaked reference carrying an explicit CSpace invoke depth.
    pub const fn at_depth(addr: Cap, depth: u8) -> Self {
        Self(CapRef::at_depth(addr, depth))
    }

    /// Borrow as a plain [`CapRef`] for an invocation.
    pub const fn cap_ref(self) -> CapRef {
        self.0
    }

    /// The raw slot address, for staging into the IPC buffer / syscall args.
    pub const fn addr(self) -> Cap {
        self.0.addr()
    }

    pub const fn depth(self) -> u8 {
        self.0.depth()
    }

    pub const fn is_null(self) -> bool {
        self.0.is_null()
    }
}

impl From<LeakedCapRef> for CapRef {
    fn from(leaked: LeakedCapRef) -> Self {
        leaked.0
    }
}

// ---------------------------------------------------------------------------
// Syscall return shape — error register + value register.
// ---------------------------------------------------------------------------

/// Result of a raw syscall: `error` is `KERNITE_OK` (0) on success,
/// otherwise a `KERNITE_ERR_*` code. `value` carries the return
/// payload (badge, MP record label, clock tick, retype slot, etc.).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaResult {
    pub error: u64,
    pub value: u64,
}

// ---------------------------------------------------------------------------
// Userland IPC message wrap and per-thread context.
// ---------------------------------------------------------------------------

/// Userland IPC message — staging shape that substrate/wrapper code
/// fills before invoking syscalls. The kernel boundary itself uses
/// `kernite_ipc_buffer` (bindgen output `uapi::kernite_ipc_buffer`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaMsg {
    pub label: u64,
    pub length: u64,
    pub regs: [u64; 32],
}

impl TronaMsg {
    /// Return a zero-initialized message (label=0, length=0, all
    /// regs=0).
    pub const fn zeroed() -> Self {
        TronaMsg {
            label: 0,
            length: 0,
            regs: [0; 32],
        }
    }
}

impl Default for TronaMsg {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// Number of `u64` words in the IPC buffer's reserved payload area.
pub const IPC_BUFFER_RESERVED_WORDS: usize = 468;
/// Number of bytes in the IPC buffer's reserved payload area.
pub const IPC_BUFFER_RESERVED_BYTES: usize =
    IPC_BUFFER_RESERVED_WORDS * core::mem::size_of::<u64>();
/// `reserved[0]` carries the receive-slot path depth for nested cap
/// delivery.
pub const IPC_BUFFER_RECV_SLOT_DEPTH_INDEX: usize = 0;
/// `reserved[1..]` is available for extended syscall payloads.
pub const IPC_BUFFER_RESERVED_PAYLOAD_BASE: usize = IPC_BUFFER_RECV_SLOT_DEPTH_INDEX + 1;
/// Maximum number of endpoint slots that fit in the extended payload
/// area.
pub const IPC_BUFFER_RECV_ANY_ENDPOINT_WORDS: usize =
    IPC_BUFFER_RESERVED_WORDS - IPC_BUFFER_RESERVED_PAYLOAD_BASE;

/// Per-thread IPC context: pointer to the kernel-mapped IPC buffer
/// page and the count of caps staged for the next send.
#[repr(C)]
pub struct IpcContext {
    /// Pointer to the kernel-shared IPC buffer page
    /// (`uapi::kernite_ipc_buffer`).
    pub ipc_buffer: *mut uapi::kernite_ipc_buffer,
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

// ---------------------------------------------------------------------------
// Child CSpace layout — passed through the SaltyOS startup block.
// ---------------------------------------------------------------------------

/// Producers (init) compute the usable slot ranges for the child and
/// place a pointer here in `SaltyOSStartupLayoutV1.cspace_layout_ptr`.
/// Consumers (rtld / CRT / userland) treat the half-open ranges as
/// the source of truth. `[alloc_base, alloc_limit)` is an allocator
/// envelope: reserved holes such as `[recv_base, recv_limit)` and
/// `[expand_base, expand_limit)` must be excluded before handing
/// slots to the general allocator.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyOSCspaceLayoutV1 {
    pub version: u64,
    pub flags: u64,
    pub cnode_bits: u64,
    pub rtld_untyped_base: u64,
    pub rtld_untyped_count: u64,
    /// Size (as power of 2) of every untyped capability in the
    /// RTLD-mirrored window `[rtld_untyped_base, rtld_untyped_base
    /// + rtld_untyped_count)`. Producers (init) populate this so
    /// rsrcsrv can pass `size_bits` to its multi-class allocator
    /// without re-querying the kernel. The window is uniform — every
    /// untyped in it shares this value.
    pub rtld_untyped_size_bits: u64,
    pub frame_slot_base: u64,
    pub frame_slot_limit: u64,
    pub alloc_base: u64,
    pub alloc_limit: u64,
    pub recv_base: u64,
    pub recv_limit: u64,
    pub expand_base: u64,
    pub expand_limit: u64,
}

impl SaltyOSCspaceLayoutV1 {
    pub const VERSION: u64 = 1;
    pub const FLAG_HAS_RECV_RANGE: u64 = 1 << 0;
    pub const FLAG_HAS_EXPAND_RANGE: u64 = 1 << 1;

    pub const fn zeroed() -> Self {
        SaltyOSCspaceLayoutV1 {
            version: 0,
            flags: 0,
            cnode_bits: 0,
            rtld_untyped_base: 0,
            rtld_untyped_count: 0,
            rtld_untyped_size_bits: 0,
            frame_slot_base: 0,
            frame_slot_limit: 0,
            alloc_base: 0,
            alloc_limit: 0,
            recv_base: 0,
            recv_limit: 0,
            expand_base: 0,
            expand_limit: 0,
        }
    }

    pub const fn alloc_envelope_count(&self) -> u64 {
        if self.alloc_limit > self.alloc_base {
            self.alloc_limit - self.alloc_base
        } else {
            0
        }
    }

    pub const fn alloc_count(&self) -> u64 {
        self.alloc_envelope_count()
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

// ---------------------------------------------------------------------------
// Process-startup handoff (auxv `AT_SALTYOS_STARTUP`).
//
// Kernel-facing / ELF-standard fields stay in auxv (`AT_PHDR`,
// `AT_PHNUM`, `AT_BASE`, ...). Everything SaltyOS-private is grouped
// behind a single validated pointer carried in `AT_SALTYOS_STARTUP`.
// ---------------------------------------------------------------------------

/// auxv tag for the SaltyOS startup descriptor pointer.
///
/// Substrate-owned because it is part of the SaltyOS startup contract,
/// not the raw kernel ABI. The bootstrap path (rtld / static CRT)
/// reads this tag from auxv and hands the pointer to substrate via
/// `runtime_set_auxv()`.
pub const AT_SALTYOS_STARTUP: u64 = 0x2005;

pub const SALTYOS_IMAGE_KIND_NONE: u32 = 0;
pub const SALTYOS_IMAGE_KIND_ELF: u32 = 1;
pub const SALTYOS_IMAGE_KIND_PE: u32 = 2;
pub const SALTYOS_STARTUP_MAX_MAPPED_IMAGES: usize = 16;
pub const SALTYOS_STARTUP_IMAGE_NAME_LEN: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyOSImageInfoV1 {
    pub kind: u32,
    pub aux: u32,
    pub base: u64,
    pub size: u64,
    pub entry: u64,
}

impl SaltyOSImageInfoV1 {
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            kind: SALTYOS_IMAGE_KIND_NONE,
            aux: 0,
            base: 0,
            size: 0,
            entry: 0,
        }
    }

    #[inline(always)]
    pub const fn new(kind: u32, aux: u32, base: u64, size: u64, entry: u64) -> Self {
        Self {
            kind,
            aux,
            base,
            size,
            entry,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyOSMappedImageV1 {
    pub image: SaltyOSImageInfoV1,
    pub name_len: u32,
    pub name: [u8; SALTYOS_STARTUP_IMAGE_NAME_LEN],
}

impl SaltyOSMappedImageV1 {
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            image: SaltyOSImageInfoV1::zeroed(),
            name_len: 0,
            name: [0; SALTYOS_STARTUP_IMAGE_NAME_LEN],
        }
    }

    #[inline(always)]
    pub fn set_name(&mut self, value: &[u8]) {
        let len = core::cmp::min(value.len(), SALTYOS_STARTUP_IMAGE_NAME_LEN);
        self.name_len = len as u32;
        let mut i = 0usize;
        while i < len {
            self.name[i] = value[i];
            i += 1;
        }
        while i < SALTYOS_STARTUP_IMAGE_NAME_LEN {
            self.name[i] = 0;
            i += 1;
        }
    }

    #[inline(always)]
    pub fn name_bytes(&self) -> &[u8] {
        let len = core::cmp::min(self.name_len as usize, SALTYOS_STARTUP_IMAGE_NAME_LEN);
        &self.name[..len]
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyOSFramebufferInfoV1 {
    pub phys_addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub red_pos: u8,
    pub red_size: u8,
    pub green_pos: u8,
    pub green_size: u8,
    pub blue_pos: u8,
    pub blue_size: u8,
    pub reserved: u8,
}

impl SaltyOSFramebufferInfoV1 {
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            phys_addr: 0,
            width: 0,
            height: 0,
            pitch: 0,
            bpp: 0,
            red_pos: 0,
            red_size: 0,
            green_pos: 0,
            green_size: 0,
            blue_pos: 0,
            blue_size: 0,
            reserved: 0,
        }
    }

    #[inline(always)]
    pub const fn is_present(&self) -> bool {
        self.phys_addr != 0 && self.width != 0 && self.height != 0 && self.pitch != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyOSStartupLayoutV1 {
    pub magic: u32,
    pub version: u32,
    pub flags: u64,
    pub ipc_buffer_vaddr: u64,
    pub scratch_vaddr: u64,
    pub dso_window_base: u64,
    pub dso_window_size: u64,
    pub cap_table_ptr: u64,
    pub cspace_layout_ptr: u64,
    pub boot_untyped_slot: u64,
    pub boot_untyped_size_bits: u64,
    pub boot_untyped_size_bytes: u64,
    pub boot_untyped_available_bytes: u64,
    pub main_image: SaltyOSImageInfoV1,
    pub mapped_image_count: u64,
    pub mapped_images: [SaltyOSMappedImageV1; SALTYOS_STARTUP_MAX_MAPPED_IMAGES],
    /// Bitmap of child VFS client-state slots the spawner
    /// pre-populated before the child's first instruction. Bit `N`
    /// set means `client.slots[N]` already holds an `ObjectRef` and
    /// the child must not open a replacement. Personalities decide
    /// what slot `N` means (POSIX: fd `N`; Win32: slot `N` is the
    /// backing for `STD_INPUT_HANDLE` / `STD_OUTPUT_HANDLE` /
    /// `STD_ERROR_HANDLE` for `N ∈ {0,1,2}`). Width covers the full
    /// `MAX_CLIENT_OBJECTS = 128` slot table; word 0 is slots 0..64,
    /// word 1 is slots 64..128.
    pub preinstalled_slot_bitmap: [u64; 2],
    /// Device metadata paired with `ROLE_FB_UNTYPED`. The framebuffer
    /// memory itself is still authority-gated by the capability; this
    /// value only describes the range and pixel layout.
    pub framebuffer: SaltyOSFramebufferInfoV1,
}

impl SaltyOSStartupLayoutV1 {
    pub const MAGIC: u32 = 0x3154_4C53; // "SLT1"
    pub const VERSION: u32 = 1;

    #[inline(always)]
    pub const fn zeroed() -> Self {
        SaltyOSStartupLayoutV1 {
            magic: 0,
            version: 0,
            flags: 0,
            ipc_buffer_vaddr: 0,
            scratch_vaddr: 0,
            dso_window_base: 0,
            dso_window_size: 0,
            cap_table_ptr: 0,
            cspace_layout_ptr: 0,
            boot_untyped_slot: 0,
            boot_untyped_size_bits: 0,
            boot_untyped_size_bytes: 0,
            boot_untyped_available_bytes: 0,
            main_image: SaltyOSImageInfoV1::zeroed(),
            mapped_image_count: 0,
            mapped_images: [SaltyOSMappedImageV1::zeroed(); SALTYOS_STARTUP_MAX_MAPPED_IMAGES],
            preinstalled_slot_bitmap: [0; 2],
            framebuffer: SaltyOSFramebufferInfoV1::zeroed(),
        }
    }

    #[inline(always)]
    pub const fn new(
        ipc_buffer_vaddr: u64,
        scratch_vaddr: u64,
        dso_window_base: u64,
        dso_window_size: u64,
        cap_table_ptr: u64,
        cspace_layout_ptr: u64,
    ) -> Self {
        SaltyOSStartupLayoutV1 {
            magic: Self::MAGIC,
            version: Self::VERSION,
            flags: 0,
            ipc_buffer_vaddr,
            scratch_vaddr,
            dso_window_base,
            dso_window_size,
            cap_table_ptr,
            cspace_layout_ptr,
            boot_untyped_slot: 0,
            boot_untyped_size_bits: 0,
            boot_untyped_size_bytes: 0,
            boot_untyped_available_bytes: 0,
            main_image: SaltyOSImageInfoV1::zeroed(),
            mapped_image_count: 0,
            mapped_images: [SaltyOSMappedImageV1::zeroed(); SALTYOS_STARTUP_MAX_MAPPED_IMAGES],
            preinstalled_slot_bitmap: [0; 2],
            framebuffer: SaltyOSFramebufferInfoV1::zeroed(),
        }
    }

    #[inline(always)]
    pub const fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version == Self::VERSION
    }

    /// Return `true` if slot `n` is flagged as pre-populated.
    /// Out-of-range indices return `false`.
    #[inline(always)]
    pub const fn slot_preinstalled(&self, n: usize) -> bool {
        if n >= 128 {
            return false;
        }
        let word = n / 64;
        let bit = n % 64;
        (self.preinstalled_slot_bitmap[word] & (1u64 << bit)) != 0
    }

    /// Set the preinstalled flag for slot `n`. Out-of-range indices
    /// are ignored.
    #[inline(always)]
    pub const fn set_slot_preinstalled(&mut self, n: usize) {
        if n >= 128 {
            return;
        }
        let word = n / 64;
        let bit = n % 64;
        self.preinstalled_slot_bitmap[word] |= 1u64 << bit;
    }

    #[inline(always)]
    pub fn set_main_image(&mut self, image: SaltyOSImageInfoV1) {
        self.main_image = image;
    }

    #[inline(always)]
    pub fn push_mapped_image(&mut self, image: SaltyOSImageInfoV1, name: &[u8]) -> bool {
        let idx = self.mapped_image_count as usize;
        if idx >= SALTYOS_STARTUP_MAX_MAPPED_IMAGES {
            return false;
        }
        let mut slot = SaltyOSMappedImageV1::zeroed();
        slot.image = image;
        slot.set_name(name);
        self.mapped_images[idx] = slot;
        self.mapped_image_count += 1;
        true
    }

    #[inline(always)]
    pub fn set_framebuffer(&mut self, framebuffer: SaltyOSFramebufferInfoV1) {
        self.framebuffer = framebuffer;
    }
}

// ---------------------------------------------------------------------------
// Substrate runtime — installed by rtld, consumed by libtrona / libc.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaRuntimeV1 {
    pub magic: u32,
    pub version: u32,
    pub flags: u64,
    pub auxv_ptr: u64,
    pub startup_ptr: u64,
    pub cap_table_ptr: u64,
    pub cspace_layout_ptr: u64,
    pub ipc_buffer_vaddr: u64,
    pub next_free_slot: u64,
    pub sc_cap: u64,
    pub tls_template: u64,
    pub tls_filesz: u64,
    pub tls_memsz: u64,
    pub tls_align: u64,
    pub tls_module_count: u64,
    pub tls_modules: [StaticTlsModule; MAX_STATIC_TLS_MODULES],
    pub pe_abi_tp: u64,
    pub pe_tls_vector_len: u64,
    pub pe_tls_module_count: u64,
    pub pe_tls_modules: [PeTlsModuleV1; MAX_PE_TLS_MODULES],
}

impl TronaRuntimeV1 {
    pub const MAGIC: u32 = 0x3154_5254; // "TRT1"
    pub const VERSION: u32 = 1;

    pub const fn zeroed() -> Self {
        Self {
            magic: 0,
            version: 0,
            flags: 0,
            auxv_ptr: 0,
            startup_ptr: 0,
            cap_table_ptr: 0,
            cspace_layout_ptr: 0,
            ipc_buffer_vaddr: 0,
            next_free_slot: 0,
            sc_cap: 0,
            tls_template: 0,
            tls_filesz: 0,
            tls_memsz: 0,
            tls_align: 1,
            tls_module_count: 0,
            tls_modules: [StaticTlsModule::zeroed(); MAX_STATIC_TLS_MODULES],
            pe_abi_tp: 0,
            pe_tls_vector_len: 0,
            pe_tls_module_count: 0,
            pe_tls_modules: [PeTlsModuleV1::zeroed(); MAX_PE_TLS_MODULES],
        }
    }

    pub const fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version == Self::VERSION
    }
}

// ---------------------------------------------------------------------------
// dlfcn / dl_iterate_phdr handoff — populated by rtld, consumed by
// libc.
// ---------------------------------------------------------------------------

/// `dladdr` result populated by rtld and returned by libc's shim.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlInfo {
    pub dli_fname: *const u8,
    pub dli_fbase: *mut u8,
    pub dli_sname: *const u8,
    pub dli_saddr: *mut u8,
}

unsafe impl Send for DlInfo {}
unsafe impl Sync for DlInfo {}

impl DlInfo {
    pub const fn zeroed() -> Self {
        DlInfo {
            dli_fname: core::ptr::null(),
            dli_fbase: core::ptr::null_mut(),
            dli_sname: core::ptr::null(),
            dli_saddr: core::ptr::null_mut(),
        }
    }
}

/// `dl_iterate_phdr` per-object descriptor. `dlpi_phdr` is an
/// `Elf64_Phdr*` in C; typed as `*const u8` here so substrate does
/// not have to pull in loader ELF type definitions.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlPhdrInfo {
    pub dlpi_addr: u64,
    pub dlpi_name: *const u8,
    pub dlpi_phdr: *const u8,
    pub dlpi_phnum: u16,
    pub _pad0: u16,
    pub _pad1: u32,
}

unsafe impl Send for DlPhdrInfo {}
unsafe impl Sync for DlPhdrInfo {}

impl DlPhdrInfo {
    pub const fn zeroed() -> Self {
        DlPhdrInfo {
            dlpi_addr: 0,
            dlpi_name: core::ptr::null(),
            dlpi_phdr: core::ptr::null(),
            dlpi_phnum: 0,
            _pad0: 0,
            _pad1: 0,
        }
    }
}

/// Callback signature for `dl_iterate_phdr`.
pub type DlIterateCallback =
    unsafe extern "C" fn(info: *mut DlPhdrInfo, size: usize, data: *mut u8) -> i32;

/// Bit set carried by `TronaLoaderRuntimeV1.flags`. Reserved for
/// future loader feature negotiation; currently always `0`.
pub type LoaderFlag = u64;

/// Opaque DTV (dynamic thread vector) handle. The rtld owns the
/// layout; libc only stores a pointer in
/// `ThreadLocalBlock::dynamic_tls` and never dereferences it.
#[repr(C)]
pub struct DynamicTlsVector {
    _opaque: [u8; 0],
}

unsafe impl Send for DynamicTlsVector {}
unsafe impl Sync for DynamicTlsVector {}

/// rtld-published function table. libc looks the table up via
/// `trona::loader_dlfcn()` and dispatches.
///
/// Every entry takes a caller-supplied error buffer as its last two
/// parameters. The rtld writes a NUL-terminated UTF-8 message into
/// the buffer when the call fails. `errbuf == null` or `errbuf_len
/// == 0` suppresses error reporting.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtldDlfcnV1 {
    pub dlopen: unsafe extern "C" fn(
        path: *const u8,
        flags: i32,
        errbuf: *mut u8,
        errbuf_len: usize,
    ) -> *mut u8,
    pub dlsym_from: unsafe extern "C" fn(
        handle: *mut u8,
        symbol: *const u8,
        caller_pc: usize,
        errbuf: *mut u8,
        errbuf_len: usize,
    ) -> *mut u8,
    pub dlclose: unsafe extern "C" fn(handle: *mut u8, errbuf: *mut u8, errbuf_len: usize) -> i32,
    pub dladdr: unsafe extern "C" fn(
        addr: *const u8,
        info: *mut DlInfo,
        errbuf: *mut u8,
        errbuf_len: usize,
    ) -> i32,
    pub dl_iterate_phdr: unsafe extern "C" fn(
        callback: DlIterateCallback,
        data: *mut u8,
        errbuf: *mut u8,
        errbuf_len: usize,
    ) -> i32,
    pub tls_addr: unsafe extern "C" fn(
        module: u64,
        offset: u64,
        errbuf: *mut u8,
        errbuf_len: usize,
    ) -> *mut u8,
    pub tls_destroy: unsafe extern "C" fn(thread_id: u64, errbuf: *mut u8, errbuf_len: usize),
}

/// Loader runtime — published by rtld, installed into libtrona via
/// `trona_loader_runtime_install`, looked up by libc through
/// `trona::loader_runtime()` / `trona::loader_dlfcn()`. Independent
/// magic and version from `TronaRuntimeV1` so the loader ABI evolves
/// separately.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaLoaderRuntimeV1 {
    pub magic: u32,
    pub version: u32,
    pub flags: u64,
    pub dlfcn: RtldDlfcnV1,
}

impl TronaLoaderRuntimeV1 {
    /// Magic bytes "TLRT" (Trona Loader Runtime).
    pub const MAGIC: u32 = 0x5452_4C54;
    pub const VERSION: u32 = 1;

    pub const fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version == Self::VERSION
    }
}

// ---------------------------------------------------------------------------
// Startup capability table — single point of cap delivery from
// spawner to child, referenced via `SaltyOSStartupLayoutV1.cap_table_ptr`.
// ---------------------------------------------------------------------------

/// One row per cap delivered to the child. `role_id` tells the
/// consumer which semantic role the slot fulfils (see
/// `role_consts.rs`); `slot` is the child-cspace slot number where
/// the spawner placed the cap; `rights` and `flags` are advisory
/// hints (see `CAP_TBL_RIGHT_*` / `CAP_TBL_FLAG_*`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyOSCapEntryV1 {
    pub role_id: u32,
    pub slot: u32,
    pub rights: u32,
    pub flags: u32,
}

impl SaltyOSCapEntryV1 {
    pub const fn zeroed() -> Self {
        SaltyOSCapEntryV1 {
            role_id: 0,
            slot: 0,
            rights: 0,
            flags: 0,
        }
    }
}

/// Layout: fixed 16-byte header followed by `count` flexible
/// entries. The table is written into a spawner-side scratch page
/// that is mapped into the child's VA; the child reads it once at
/// startup to populate weak symbol slots (system roles).
/// Service-local roles (`role_id >= LOCAL_ROLE_BASE`) are not
/// installed into weak symbols — consumers resolve them on demand
/// via `trona::caps::local_by_name` or the `trona::local_cap!`
/// macro, which read directly from this table.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyOSCapTableV1 {
    pub magic: u32,
    pub version: u32,
    pub count: u32,
    pub reserved: u32,
    /// Flexible array — real length is `count`, reached via pointer
    /// arithmetic from the end of this header.
    pub entries: [SaltyOSCapEntryV1; 0],
}

impl SaltyOSCapTableV1 {
    pub const fn zeroed() -> Self {
        SaltyOSCapTableV1 {
            magic: 0,
            version: 0,
            count: 0,
            reserved: 0,
            entries: [],
        }
    }
}

const _: [(); core::mem::size_of::<SaltyOSImageInfoV1>()] =
    [(); core::mem::size_of::<uapi::SaltyOSImageInfoV1>()];
const _: [(); core::mem::size_of::<SaltyOSMappedImageV1>()] =
    [(); core::mem::size_of::<uapi::SaltyOSMappedImageV1>()];
const _: [(); core::mem::size_of::<SaltyOSFramebufferInfoV1>()] =
    [(); core::mem::size_of::<uapi::SaltyOSFramebufferInfoV1>()];
const _: [(); core::mem::size_of::<SaltyOSStartupLayoutV1>()] =
    [(); core::mem::size_of::<uapi::SaltyOSStartupLayoutV1>()];
const _: [(); core::mem::size_of::<SaltyOSCspaceLayoutV1>()] =
    [(); core::mem::size_of::<uapi::SaltyOSCspaceLayoutV1>()];
const _: [(); core::mem::size_of::<SaltyOSCapEntryV1>()] =
    [(); core::mem::size_of::<uapi::SaltyOSCapEntryV1>()];

// ---------------------------------------------------------------------------
// Lowered service-attachment registry (init's parser shape).
// ---------------------------------------------------------------------------

/// Maximum length of a provider service name in a lowered attachment
/// entry. Must equal `ini::MAX_SERVICE_NAME` (currently 32).
pub const MAX_REQUIRE_PROVIDER: usize = 32;

/// Maximum length of a service-local alias / system attribute suffix.
pub const MAX_REQUIRE_ALIAS: usize = 24;

/// Maximum number of lowered attachment descriptors carried in
/// init's parser / build-tool helper state.
pub const MAX_REQUIRES: usize = 8;

/// `TronaRequireDefV1.kind` — provider lives in the system
/// namespace.
pub const REQUIRE_KIND_SYSTEM: u8 = 0;
/// `TronaRequireDefV1.kind` — provider lives in the service
/// namespace.
pub const REQUIRE_KIND_LOCAL: u8 = 1;
/// `TronaRequireDefV1.attachment_type` — endpoint attachment.
pub const ATTACHMENT_TYPE_ENDPOINT: u8 = 0;
/// `TronaRequireDefV1.attachment_type` — capability attachment.
pub const ATTACHMENT_TYPE_CAP: u8 = 1;

/// Parsed lowered attachment entry in its parser / build-tool shape.
///
/// Used by init's typed-unit lowering and build-time tooling. This
/// struct is **not** the lowered registry shape — see
/// `TronaServiceAttachment` for that. The lowered form drops `alias`
/// because the runtime registry only needs `role_id` (already
/// resolved at parse time) and `provider` (for provider-registry
/// lookup).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaRequireDefV1 {
    pub provider: [u8; MAX_REQUIRE_PROVIDER],
    pub provider_len: u8,
    pub alias: [u8; MAX_REQUIRE_ALIAS],
    pub alias_len: u8,
    pub kind: u8,
    pub attachment_type: u8,
    pub badged: u8,
    pub raw: u8,
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
            attachment_type: ATTACHMENT_TYPE_ENDPOINT,
            badged: 0,
            raw: 0,
            role_id: 0,
        }
    }
}

/// Magic for `TronaServiceDefs` — bytes spell `"PMSD"` little-endian.
/// Distinct from `SALTYOS_CAP_TABLE_MAGIC` so a malformed transfer
/// cannot be misread as a cap table.
pub const TRONA_SERVICE_DEFS_MAGIC: u32 = 0x44534D50;

/// `TronaServiceDefs.flags` — this chunk starts a new registry
/// stream.
pub const TRONA_SERVICE_DEFS_FLAG_FIRST: u32 = 1 << 0;
/// `TronaServiceDefs.flags` — this chunk is the final registry
/// chunk.
pub const TRONA_SERVICE_DEFS_FLAG_LAST: u32 = 1 << 1;

/// One lowered attachment entry as the registry consumer sees it.
///
/// Narrower than `TronaRequireDefV1`: the `alias` field is dropped
/// because the registry never needs it — `role_id` is pre-resolved
/// by init, and provider lookup uses `provider` only. The lowered
/// entry still carries both the provider namespace (`kind`) and the
/// attachment family (`attachment_type`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaServiceAttachment {
    pub provider: [u8; MAX_REQUIRE_PROVIDER],
    pub provider_len: u8,
    pub kind: u8,
    pub attachment_type: u8,
    pub badged: u8,
    pub raw: u8,
    pub _pad: [u8; 3],
    pub role_id: u32,
}

impl TronaServiceAttachment {
    pub const fn zeroed() -> Self {
        TronaServiceAttachment {
            provider: [0; MAX_REQUIRE_PROVIDER],
            provider_len: 0,
            kind: REQUIRE_KIND_SYSTEM,
            attachment_type: ATTACHMENT_TYPE_ENDPOINT,
            badged: 0,
            raw: 0,
            _pad: [0; 3],
            role_id: 0,
        }
    }
}

/// One service def as the registry consumer sees it.
///
/// `name` is the service name (also the spawn binary key in init's
/// provider registry). `bootstrap_privileged` gates
/// `*_AUTHORITY_RAW` roles. `(attachment_start, attachment_count)`
/// names the subrange in the chunk's trailing
/// `TronaServiceAttachment[]` array that belongs to this service.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaServiceDef {
    pub name: [u8; MAX_REQUIRE_PROVIDER],
    pub name_len: u8,
    pub bootstrap_privileged: u8,
    pub _pad: u16,
    /// Init-owned permanent slot for this service's listener /
    /// provider cap. Init always lowers this as 0; the registry
    /// consumer fills it in later when the provider is registered.
    pub provider_slot: u64,
    pub attachment_start: u32,
    pub attachment_count: u32,
}

impl TronaServiceDef {
    pub const fn zeroed() -> Self {
        TronaServiceDef {
            name: [0; MAX_REQUIRE_PROVIDER],
            name_len: 0,
            bootstrap_privileged: 0,
            _pad: 0,
            provider_slot: 0,
            attachment_start: 0,
            attachment_count: 0,
        }
    }
}

/// Top-level header for the service-def registry. Layout: fixed
/// header followed by `service_count` `TronaServiceDef` entries and
/// then `attachment_count` `TronaServiceAttachment` entries. One
/// header per registry chunk; the `flags` FIRST / LAST markers
/// delimit a multi-chunk stream.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaServiceDefs {
    pub magic: u32,
    pub flags: u32,
    pub service_count: u32,
    pub attachment_count: u32,
    pub reserved: u64,
    /// Flexible array — real length is `service_count`, reached via
    /// pointer arithmetic from the end of this header.
    pub services: [TronaServiceDef; 0],
}

impl TronaServiceDefs {
    pub const fn zeroed() -> Self {
        TronaServiceDefs {
            magic: 0,
            flags: 0,
            service_count: 0,
            attachment_count: 0,
            reserved: 0,
            services: [],
        }
    }
}

// ---------------------------------------------------------------------------
// TLS metadata — shared between substrate globals and the TLS layer.
// ---------------------------------------------------------------------------

/// Maximum number of static TLS modules exported by rtld.
pub const MAX_STATIC_TLS_MODULES: usize = 8;
/// Maximum number of PE TLS modules exported by rtld.
pub const MAX_PE_TLS_MODULES: usize = 16;
/// First TLS module ID reserved for runtime-loaded (dlopen) modules.
///
/// Static modules registered at process startup occupy
/// `1..=MAX_STATIC_TLS_MODULES`. Dynamic modules issued by the rtld
/// at runtime live above this constant. Both libc and the rtld read
/// this value to decide whether `__tls_get_addr` should dispatch
/// through the static or DTV path.
pub const DYNAMIC_TLS_MODULE_BASE: u64 = 17;

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

/// Per-module PE TLS metadata exported by rtld.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PeTlsModuleV1 {
    pub tls_index: u32,
    pub reserved: u32,
    pub template_addr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

impl PeTlsModuleV1 {
    pub const fn zeroed() -> Self {
        Self {
            tls_index: 0,
            reserved: 0,
            template_addr: 0,
            filesz: 0,
            memsz: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TLS block layout — shared between substrate and personality layers.
// ---------------------------------------------------------------------------

/// Cleanup handler node for `pthread_cleanup_push` / `pop`.
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
/// Layout is `#[repr(C)]` for ABI stability. The `self_ptr` field
/// MUST be first — the x86_64 TLS ABI mandates that `%fs:0`
/// dereferences to the TLS block's own address.
///
/// This struct is the canonical ABI type shared by substrate, POSIX,
/// Win32, and any future personality. Substrate sets `self_ptr`,
/// `ipc_ctx`, `thread_id`. POSIX adds `errno`, `cancel_*`,
/// `cleanup_stack`. The `desc` field is an opaque back-pointer to
/// the substrate `ThreadDesc`; personalities cast through it to
/// reach personality-specific extensions.
#[repr(C)]
pub struct ThreadLocalBlock {
    /// Self-pointer: `%fs:0 == &self` (x86_64 TLS ABI requirement).
    pub self_ptr: *mut ThreadLocalBlock,
    /// Per-thread IPC context (IPC buffer pointer + send-cap count).
    pub ipc_ctx: IpcContext,
    /// Thread ID (unique per thread within a process).
    pub thread_id: u64,
    /// Per-thread errno value.
    pub errno: i32,
    /// Padding for alignment.
    pub _pad0: i32,
    /// Back-pointer to substrate `ThreadDesc` (opaque — cast in
    /// substrate only).
    pub desc: *mut u8,
    /// Cancellation state: 0 = ENABLE, 1 = DISABLE.
    pub cancel_state: u32,
    /// Cancellation type: 0 = DEFERRED (only type supported).
    pub cancel_type: u32,
    /// Set to 1 when cancellation has been requested.
    pub cancel_pending: u32,
    pub _pad1: u32,
    /// LIFO stack of cleanup handlers (intrusive linked list).
    pub cleanup_stack: *mut CleanupHandler,
    /// Futex address the thread is currently blocked on (for cancel
    /// wake). Set before `futex_wait` at cancellation points,
    /// cleared after return. 0 means the thread is not blocked on
    /// any cancellation-point futex.
    pub blocked_futex_addr: core::sync::atomic::AtomicU64,

    // basaltc per-thread state (appended to preserve existing offsets).
    /// Per-thread `strtok()` save pointer.
    pub strtok_save: *mut u8,
    /// Per-thread `struct tm` buffer for `gmtime()` / `localtime()`
    /// (56 bytes).
    pub libc_tm_buf: [u8; 56],
    /// Per-thread `asctime()` buffer (64 bytes).
    pub libc_asctime_buf: [u8; 64],
    /// Per-thread `ctime()` buffer (64 bytes).
    pub libc_ctime_buf: [u8; 64],

    // rtld dlfcn per-thread state (appended; layout owned by substrate).
    /// Per-thread DTV pointer. The rtld owns the pointee layout;
    /// libc never dereferences it. Null until the first `tls_addr`
    /// call needs a dynamic module slot.
    pub dynamic_tls: *mut DynamicTlsVector,
    /// Per-thread `dlerror` message buffer pointer. libc lazy-
    /// allocates a 256-byte buffer on first dlfcn use and stores the
    /// pointer here. The rtld writes the message into this buffer;
    /// `dlerror()` returns it while clearing only the pending flag.
    pub dlerror_msg: *mut u8,
    /// Nonzero when `dlerror_msg` contains an unread error string.
    pub dlerror_pending: u64,
}

unsafe impl Send for ThreadLocalBlock {}
unsafe impl Sync for ThreadLocalBlock {}

// `self_ptr` MUST stay at offset 0 — the x86_64 TLS ABI dereferences
// `%fs:0` to obtain the TLS block address. Both rtld dlfcn fields
// are appended after the existing libc scratch buffers so prior
// offsets are unaffected.
const _: () = {
    assert!(core::mem::offset_of!(ThreadLocalBlock, self_ptr) == 0);
};

impl ThreadLocalBlock {
    /// Create a zero-initialized TLS block with `self_ptr` set to
    /// null. The caller must set `self_ptr = &mut self as *mut _`
    /// after placement.
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
            dynamic_tls: core::ptr::null_mut(),
            dlerror_msg: core::ptr::null_mut(),
            dlerror_pending: 0,
        }
    }
}

/// Minimal Win32 ABI thread-pointer block.
///
/// Compiled PE TLS access expects the thread-local storage pointer
/// vector at offset `0x58` from the active ABI thread pointer
/// (`%gs` on x86_64, `x18` on aarch64). RTLD seeds one of these
/// blocks per PE thread and points the architecture-specific ABI
/// register at it.
#[repr(C)]
pub struct Win32ThreadPointerBlock {
    pub reserved0: [u64; 11],
    pub thread_local_storage_pointer: *mut *mut u8,
    pub runtime_tcb: *mut ThreadLocalBlock,
    pub self_ptr: *mut Win32ThreadPointerBlock,
    pub tls_vector_len: u64,
}

unsafe impl Send for Win32ThreadPointerBlock {}
unsafe impl Sync for Win32ThreadPointerBlock {}

impl Win32ThreadPointerBlock {
    pub const fn zeroed() -> Self {
        Self {
            reserved0: [0; 11],
            thread_local_storage_pointer: core::ptr::null_mut(),
            runtime_tcb: core::ptr::null_mut(),
            self_ptr: core::ptr::null_mut(),
            tls_vector_len: 0,
        }
    }
}

/// aarch64 ABI thread-pointer block. `TPIDR_EL0` points to this
/// structure. `runtime_tcb` points to the `ThreadLocalBlock` that
/// follows the ELF TLS data region.
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
