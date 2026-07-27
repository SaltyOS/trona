//! SPDX-License-Identifier: GPL-2.0-only
//! Link map and RTLD state types shared between loader and runtime

use super::elf::dynamic::DynInfo;
use super::elf::tls::{TLS_MAX_MODULES, TlsLayout, TlsModule};
use super::elf::types::*;
use core::sync::atomic::AtomicU32;

/// Maximum number of shared objects tracked by the RTLD at startup. Runtime-
/// loaded objects (dlopen) live in the [`RtldState::dl_head`] chain instead
/// of this fixed array.
pub const RTLD_MAX_OBJECTS: usize = 16;

/// Per-LinkMap status / scope flags. The bit set replaces the previous
/// `relocated` / `initialized` booleans and adds dlopen lifecycle state.
pub mod link_flags {
    /// Object was placed at startup; never unloaded by dlclose.
    pub const STARTUP: u32 = 1 << 0;
    /// Symbols belong to the global scope (RTLD_GLOBAL).
    pub const RTLD_GLOBAL: u32 = 1 << 1;
    /// Symbols belong to the per-handle local scope (RTLD_LOCAL).
    pub const RTLD_LOCAL: u32 = 1 << 2;
    /// dlclose never unmaps this object once loaded (RTLD_NODELETE / DF_1_NODELETE).
    pub const RTLD_NODELETE: u32 = 1 << 3;
    /// Object was loaded at runtime via dlopen; counterpart of `STARTUP`.
    pub const RUNTIME_LOADED: u32 = 1 << 4;
    /// All non-PLT relocations have been applied.
    pub const RELOCATED: u32 = 1 << 5;
    /// DT_INIT / DT_INIT_ARRAY ran successfully.
    pub const INIT_DONE: u32 = 1 << 6;
    /// DT_FINI / DT_FINI_ARRAY ran successfully.
    pub const FINI_DONE: u32 = 1 << 7;
}

/// Per-object link map entry (musl-style `struct dso`).
#[repr(C)]
pub struct LinkMap {
    /// Load base address (bias for ET_DYN, 0 for ET_EXEC).
    pub base: usize,
    /// Pointer to the object's name (null-terminated, in strtab or CPIO).
    pub name: *const u8,
    /// Interned full pathname for runtime-loaded objects (null for startup).
    pub path: *const u8,
    /// Interned SONAME (null when DT_SONAME is absent).
    pub soname: *const u8,
    /// Pointer to the PT_DYNAMIC segment (relocated).
    pub dynamic: *const Elf64Dyn,
    /// Parsed dynamic section info.
    pub dyn_info: DynInfo,
    /// Symbol table (relocated).
    pub symtab: *const Elf64Sym,
    /// String table (relocated).
    pub strtab: *const u8,
    /// String table size.
    pub strsz: usize,
    /// GNU hash table pointer (relocated), or null.
    pub gnu_hash: *const u32,
    /// RELA relocations (relocated).
    pub rela: *const Elf64Rela,
    /// Number of RELA entries.
    pub rela_count: usize,
    /// PLT/JMPREL relocations (relocated).
    pub jmprel: *const Elf64Rela,
    /// Number of PLT relocation entries.
    pub jmprel_count: usize,
    /// GOT pointer (relocated).
    pub pltgot: *mut usize,
    /// Program headers (relocated or mapped).
    pub phdr: *const Elf64Phdr,
    /// Number of program headers.
    pub phnum: u16,
    /// ELF type (ET_EXEC or ET_DYN).
    pub e_type: u16,
    /// Entry point (relocated).
    pub entry: usize,
    /// Start of the contiguous mapping covering all PT_LOAD segments.
    pub map_start: usize,
    /// One-past-the-end of the mapping.
    pub map_end: usize,
    /// Final (post-RELRO) protection bits applied across the mapping. Zero for
    /// objects mapped run-by-run from a code MemoryObject (each run already
    /// carries its final protection); set only for pre-mapped seed objects.
    pub map_prot: u32,
    /// mmsrv image-reservation id grouping this object's runs (`0` for a
    /// startup / pre-mapped object that is never torn down). `dlclose` tears the
    /// whole image down via `MM_UNMAP_IMAGE(image_id)`.
    pub image_id: u64,
    /// `link_flags::*` bit set.
    pub flags: u32,
    /// Reference count for dlopen / dlclose. Zero for STARTUP objects.
    pub refcount: u32,
    /// Vector of dependency `LinkMap*` pointers (DT_NEEDED transitive set).
    pub deps_ptr: *mut *mut LinkMap,
    /// Number of entries in `deps_ptr`.
    pub deps_count: u32,
    /// TLS module ID (1-based, 0 = no TLS). Static modules use the
    /// `1..=TLS_MAX_MODULES` range; dynamic modules use IDs >=
    /// `DYNAMIC_TLS_MODULE_BASE`.
    pub tls_mod_id: usize,
    /// TLS image base address.
    pub tls_image: usize,
    /// TLS initialized data size.
    pub tls_filesz: usize,
    /// TLS total size (including BSS).
    pub tls_memsz: usize,
    /// TLS alignment.
    pub tls_align: usize,
    /// Init function pointer (DT_INIT).
    pub init: usize,
    /// Fini function pointer (DT_FINI).
    pub fini: usize,
    /// Init array pointer (DT_INIT_ARRAY).
    pub init_array: usize,
    /// Init array byte size.
    pub init_arraysz: usize,
    /// Fini array pointer (DT_FINI_ARRAY).
    pub fini_array: usize,
    /// Fini array byte size.
    pub fini_arraysz: usize,
    /// DT_VERDEF table base (relocated). Null when absent.
    pub verdef: *const u8,
    /// Number of DT_VERDEF entries.
    pub verdef_num: u32,
    /// DT_VERNEED table base (relocated). Null when absent.
    pub verneed: *const u8,
    /// Number of DT_VERNEED entries.
    pub verneed_num: u32,
    /// DT_VERSYM array (relocated). Null when absent.
    pub versym: *const u16,
    /// Cached symbol-table entry count, computed once by `apply_dyn_info`
    /// from DT_HASH `nchain` (preferred) or by walking the GNU hash chains
    /// for the maximum referenced index. Used by lookup / dladdr paths to
    /// skip the per-call O(N) chain walk.
    pub nsyms: u32,
    /// DT_RUNPATH string (interned, NUL-terminated). Null when absent.
    pub runpath: *const u8,
    /// DT_RPATH string (interned, NUL-terminated). Null when absent.
    pub rpath: *const u8,
    /// dlopen chain — next link.
    pub l_next: *mut LinkMap,
    /// dlopen chain — previous link.
    pub l_prev: *mut LinkMap,
}

unsafe impl Send for LinkMap {}
unsafe impl Sync for LinkMap {}

impl LinkMap {
    pub const fn zeroed() -> Self {
        Self {
            base: 0,
            name: core::ptr::null(),
            path: core::ptr::null(),
            soname: core::ptr::null(),
            dynamic: core::ptr::null(),
            dyn_info: DynInfo {
                strtab: 0,
                strsz: 0,
                symtab: 0,
                syment: 0,
                rela: 0,
                relasz: 0,
                relaent: 0,
                jmprel: 0,
                pltrelsz: 0,
                pltgot: 0,
                pltrel: 0,
                init: 0,
                fini: 0,
                init_array: 0,
                init_arraysz: 0,
                fini_array: 0,
                fini_arraysz: 0,
                gnu_hash: 0,
                hash: 0,
                soname: 0,
                flags: 0,
                flags_1: 0,
                rpath: 0,
                runpath: 0,
                verdef: 0,
                verdef_num: 0,
                verneed: 0,
                verneed_num: 0,
                versym: 0,
            },
            symtab: core::ptr::null(),
            strtab: core::ptr::null(),
            strsz: 0,
            gnu_hash: core::ptr::null(),
            rela: core::ptr::null(),
            rela_count: 0,
            jmprel: core::ptr::null(),
            jmprel_count: 0,
            pltgot: core::ptr::null_mut(),
            phdr: core::ptr::null(),
            phnum: 0,
            e_type: 0,
            entry: 0,
            map_start: 0,
            map_end: 0,
            map_prot: 0,
            image_id: 0,
            flags: 0,
            refcount: 0,
            deps_ptr: core::ptr::null_mut(),
            deps_count: 0,
            tls_mod_id: 0,
            tls_image: 0,
            tls_filesz: 0,
            tls_memsz: 0,
            tls_align: 0,
            init: 0,
            fini: 0,
            init_array: 0,
            init_arraysz: 0,
            fini_array: 0,
            fini_arraysz: 0,
            verdef: core::ptr::null(),
            verdef_num: 0,
            verneed: core::ptr::null(),
            verneed_num: 0,
            versym: core::ptr::null(),
            nsyms: 0,
            runpath: core::ptr::null(),
            rpath: core::ptr::null(),
            l_next: core::ptr::null_mut(),
            l_prev: core::ptr::null_mut(),
        }
    }

    /// Test whether `flag` (a `link_flags::*` constant) is set.
    #[inline]
    pub const fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// Set `flag` (idempotent, no synchronization).
    #[inline]
    pub fn set_flag(&mut self, flag: u32) {
        self.flags |= flag;
    }

    /// Clear `flag` (idempotent, no synchronization).
    #[inline]
    pub fn clear_flag(&mut self, flag: u32) {
        self.flags &= !flag;
    }
}

/// Bump arena owned by the rtld. Backing pages come from rtld-private mmsrv
/// IPC helpers and live for the remainder of the process.
/// Used to allocate `LinkMap` slots, dependency vectors, DTV slabs, and
/// interned path / SONAME strings.
#[repr(C)]
pub struct ArenaState {
    /// Mapping base (page-aligned).
    pub base: usize,
    /// Total mapping size in bytes.
    pub size: usize,
    /// Bump cursor — next free byte offset from `base`.
    pub cursor: usize,
    /// Lock guarding `cursor`.
    pub lock: ::trona_runtime::thread::worker::SpinLock,
}

impl ArenaState {
    pub const fn zeroed() -> Self {
        Self {
            base: 0,
            size: 0,
            cursor: 0,
            lock: ::trona_runtime::thread::worker::SpinLock::new(),
        }
    }
}

/// Global RTLD state.
#[repr(C)]
pub struct RtldState {
    /// Boot-time link map seed (slot 0 = RTLD itself, slot 1 = main
    /// executable, 2.. = preloaded dependencies). Runtime-loaded objects do
    /// not occupy this array; they live in the [`Self::dl_head`] chain only.
    pub objects: [LinkMap; RTLD_MAX_OBJECTS],
    /// Number of populated `objects` slots.
    pub count: usize,
    /// TLS layout.
    pub tls_layout: TlsLayout,
    /// TLS module descriptors.
    pub tls_modules: [TlsModule; TLS_MAX_MODULES],
    /// Shared library load address cursor.
    pub lib_load_addr: usize,
    /// End of the reserved shared-library window (0 = unbounded fallback).
    pub lib_load_limit: usize,
    /// Next mirrored generic-untyped slot available to rtld.
    pub next_untyped_slot: u32,
    /// One-past-the-end of the mirrored generic-untyped window.
    pub untyped_limit: u32,
    /// Next available CNode frame slot.
    pub next_free_slot: u32,
    /// One-past-the-end of the RTLD-owned persistent frame slot range.
    pub frame_slot_limit: u32,
    /// Scheduling context cap slot.
    pub sc_cap: u32,
    /// Current thread's installed PE ABI thread pointer base.
    pub pe_abi_tp: usize,
    /// Number of slots in the PE TLS vector.
    pub pe_tls_vector_len: usize,
    /// Number of published PE TLS modules.
    pub pe_tls_module_count: usize,
    /// Per-module PE TLS metadata.
    pub pe_tls_modules: [PeTlsModuleState; trona_kernel::core_types::MAX_PE_TLS_MODULES],
    /// Head of the dlopen chain (LinkMap entries are singly anchored here
    /// regardless of whether they were loaded at startup or runtime).
    pub dl_head: *mut LinkMap,
    /// Lock guarding [`Self::dl_head`] and per-LinkMap `flags` / `refcount`
    /// mutations from dlopen / dlclose.
    pub dl_lock: ::trona_runtime::thread::worker::SpinLock,
    /// Bump arena backing LinkMap, dependency vector, DTV slab, and string
    /// interning allocations.
    pub arena: ArenaState,
    /// Counter handing out IDs in the dynamic TLS module ID space (starts at
    /// `DYNAMIC_TLS_MODULE_BASE` after startup TLS setup completes).
    pub next_dynamic_tls_module_id: AtomicU32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PeTlsModuleState {
    pub tls_index: u32,
    pub reserved: u32,
    pub template_addr: usize,
    pub filesz: usize,
    pub memsz: usize,
}

impl RtldState {
    pub const fn zeroed() -> Self {
        const ZERO_LM: LinkMap = LinkMap::zeroed();
        const ZERO_TLS: TlsModule = TlsModule {
            base: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
            offset: 0,
            mod_id: 0,
        };
        const ZERO_PE_TLS: PeTlsModuleState = PeTlsModuleState {
            tls_index: 0,
            reserved: 0,
            template_addr: 0,
            filesz: 0,
            memsz: 0,
        };
        Self {
            objects: [ZERO_LM; RTLD_MAX_OBJECTS],
            count: 0,
            tls_layout: TlsLayout {
                size: 0,
                align: 0,
                count: 0,
            },
            tls_modules: [ZERO_TLS; TLS_MAX_MODULES],
            lib_load_addr: 0,
            lib_load_limit: 0,
            next_untyped_slot: 0,
            untyped_limit: 0,
            next_free_slot: 0,
            frame_slot_limit: 0,
            sc_cap: 0,
            pe_abi_tp: 0,
            pe_tls_vector_len: 0,
            pe_tls_module_count: 0,
            pe_tls_modules: [ZERO_PE_TLS; trona_kernel::core_types::MAX_PE_TLS_MODULES],
            dl_head: core::ptr::null_mut(),
            dl_lock: ::trona_runtime::thread::worker::SpinLock::new(),
            arena: ArenaState::zeroed(),
            next_dynamic_tls_module_id: AtomicU32::new(0),
        }
    }
}

pub const CSPACE_LAYOUT_VERSION: u32 = 1;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct CspaceLayoutV1 {
    pub version: u32,
    pub flags: u32,
    pub cnode_bits: u32,
    pub frame_slot_base: u32,
    pub alloc_base: u32,
    pub alloc_limit: u32,
    pub recv_base: u32,
    pub recv_limit: u32,
    pub expand_base: u32,
    pub expand_limit: u32,
}
