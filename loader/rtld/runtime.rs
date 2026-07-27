//! SPDX-License-Identifier: GPL-2.0-only
//! RTLD startup/runtime helpers shared by ELF and PE entry paths.

use crate::common::elf::header;
use crate::common::elf::types::*;
use crate::common::link_map::{LinkMap, RtldState, link_flags};
use crate::rtld::elf::dlfcn;
use crate::rtld::elf::object;
use crate::rtld::io::AuxvInfo;
use crate::rtld::serial;
use trona_kernel::core_types::{
    DlInfo, DlIterateCallback, MAX_PE_TLS_MODULES, PeTlsModuleV1, RtldDlfcnV1, SaltyOSCapTableV1,
    TronaLoaderRuntimeV1, TronaRuntimeV1,
};

/// Register the already-mapped RTLD image into a link-map slot.
///
/// # Safety
/// Must be called during single-threaded rtld startup.
pub unsafe fn setup_rtld_object(lm: &mut LinkMap, auxv: &AuxvInfo) {
    unsafe extern "C" {
        static _DYNAMIC: Elf64Dyn;
        static __ehdr_start: Elf64Ehdr;
    }

    let ehdr = unsafe { &*(&raw const __ehdr_start) };
    let phdr = (ehdr as *const Elf64Ehdr as usize + ehdr.e_phoff as usize) as *const Elf64Phdr;
    let phdrs = unsafe { core::slice::from_raw_parts(phdr, ehdr.e_phnum as usize) };

    lm.base = auxv.at_base;
    lm.name = b"<rtld>\0".as_ptr();
    lm.dynamic = &raw const _DYNAMIC;
    lm.phdr = phdr;
    lm.phnum = ehdr.e_phnum;
    lm.e_type = ET_DYN;
    lm.entry = auxv.at_base + ehdr.e_entry as usize;
    lm.dyn_info = unsafe { crate::common::elf::dynamic::parse_dynamic(lm.dynamic) };
    unsafe { object::apply_dyn_info(lm) };

    if let Some(tls_ph) = header::find_tls_phdr(phdrs) {
        lm.tls_image = lm.base + tls_ph.p_vaddr as usize;
        lm.tls_filesz = tls_ph.p_filesz as usize;
        lm.tls_memsz = tls_ph.p_memsz as usize;
        lm.tls_align = tls_ph.p_align as usize;
    }

    // The rtld is its own loader: its segments are already in their final
    // place at this point, no PLT/GOT patching is needed for self-relocation.
    lm.set_flag(link_flags::RELOCATED);
    lm.set_flag(link_flags::INIT_DONE);
}

/// Initialize RTLD state from the startup block/cap table contract.
///
/// # Safety
/// Must be called during single-threaded rtld startup.
pub unsafe fn init_state_from_auxv(st: &mut RtldState, auxv: &AuxvInfo) {
    unsafe { init_embedded_substrate(auxv) };

    let Some(cspace_layout) = auxv.cspace_layout() else {
        serial::fatal("missing startup cspace layout");
    };
    st.next_untyped_slot = cspace_layout.rtld_untyped_base as u32;
    st.untyped_limit = cspace_layout
        .rtld_untyped_base
        .saturating_add(cspace_layout.rtld_untyped_count) as u32;
    st.next_free_slot = cspace_layout.frame_slot_base as u32;
    st.frame_slot_limit = cspace_layout.frame_slot_limit as u32;
    st.sc_cap = auxv.cap_slot(trona_runtime::spawn::role_consts::ROLE_SC_CAP);

    // Make the rtld a first-class trona client: bring up its embedded slot
    // allocator so the linker can do cap-receiving IPC (vfs lazy-resolve,
    // open-for-exec, file-backed MO mmap) while resolving DT_NEEDED libraries
    // for path exec. The window is carved from the free-slot pool and
    // `next_free_slot` advanced past it, so libtrona's allocator — which floors
    // at `next_free_slot` — stays disjoint, the same handoff frame caps use.
    // `slot_alloc_init` is the range init for RTLD/CRT startup: no self-expand,
    // so the window is fixed. It must stay within `frame_slot_limit`, below the
    // expand/recv holes `slot_alloc_init` does not exclude.
    const RTLD_ALLOC_WINDOW: u32 = 32;
    let alloc_base = st.next_free_slot;
    if alloc_base == 0 || alloc_base.saturating_add(RTLD_ALLOC_WINDOW) > st.frame_slot_limit {
        serial::fatal("rtld slot-allocator window exceeds the free-slot pool");
    }
    unsafe {
        trona_runtime::core::slot_alloc::slot_alloc_init(
            alloc_base as u64,
            RTLD_ALLOC_WINDOW as u64,
        );
    }
    st.next_free_slot = alloc_base + RTLD_ALLOC_WINDOW;
}

/// Initialize the copy of `trona` statically linked into ldtrona itself.
///
/// libtrona's globals are installed later through `trona_runtime_install`,
/// but the rtld runtime path can issue VFS/MMSRV IPC before control reaches
/// libc. Those calls use ldtrona's embedded substrate, so it needs its own
/// IPC context and well-known capability slots.
///
/// # Safety
/// `auxv` must describe the current process startup block.
unsafe fn init_embedded_substrate(auxv: &AuxvInfo) {
    unsafe {
        if auxv.ipc_buffer_vaddr != 0 {
            let ipc_buf = auxv.ipc_buffer_vaddr as *mut uapi::kernite_ipc_buffer;
            let _ = trona_kernel::invoke::tcb_set_ipc_buffer(
                trona_kernel::core_types::CapRef::flat(uapi::KERNITE_CAP_SELF_TCB as u64),
                auxv.ipc_buffer_vaddr as u64,
            );
            trona_kernel::ipc::ipc_context_init(&raw mut trona_runtime::__trona_ipc_ctx, ipc_buf);
        }
        let _ = trona_runtime::spawn::cap_table::install_well_known_caps(
            auxv.cap_table_ptr as *const SaltyOSCapTableV1,
        );
    }
}

/// Build the runtime ABI block exported by rtld to libtrona/libc.
pub fn build_runtime(st: &RtldState, auxv: &AuxvInfo) -> TronaRuntimeV1 {
    let mut runtime = TronaRuntimeV1::zeroed();
    runtime.magic = TronaRuntimeV1::MAGIC;
    runtime.version = TronaRuntimeV1::VERSION;
    runtime.auxv_ptr = auxv.raw_auxv as u64;
    runtime.startup_ptr = auxv.startup as u64;
    runtime.cap_table_ptr = auxv.cap_table_ptr as u64;
    runtime.cspace_layout_ptr = auxv.cspace_layout_ptr as u64;
    runtime.ipc_buffer_vaddr = auxv.ipc_buffer_vaddr as u64;
    runtime.next_free_slot = st.next_free_slot as u64;
    runtime.sc_cap = st.sc_cap as u64;

    if st.tls_layout.count > 0 {
        runtime.tls_align = st.tls_layout.align as u64;
        runtime.tls_memsz = st.tls_layout.size as u64;
        runtime.tls_module_count = core::cmp::min(
            st.tls_layout.count,
            trona_kernel::core_types::MAX_STATIC_TLS_MODULES,
        ) as u64;
        runtime.tls_template = st.tls_modules[0].base as u64;
        runtime.tls_filesz = st.tls_modules[0].filesz as u64;
        let mut i = 0usize;
        while i < runtime.tls_module_count as usize {
            let src = st.tls_modules[i];
            runtime.tls_modules[i] = trona_kernel::core_types::StaticTlsModule {
                module_id: src.mod_id as u64,
                template_addr: src.base as u64,
                filesz: src.filesz as u64,
                memsz: src.memsz as u64,
                tp_offset: src.offset as i64,
            };
            i += 1;
        }
    }

    runtime.pe_abi_tp = st.pe_abi_tp as u64;
    runtime.pe_tls_vector_len = st.pe_tls_vector_len as u64;
    runtime.pe_tls_module_count = core::cmp::min(st.pe_tls_module_count, MAX_PE_TLS_MODULES) as u64;
    let mut i = 0usize;
    while i < runtime.pe_tls_module_count as usize {
        let src = st.pe_tls_modules[i];
        runtime.pe_tls_modules[i] = PeTlsModuleV1 {
            tls_index: src.tls_index,
            reserved: 0,
            template_addr: src.template_addr as u64,
            filesz: src.filesz as u64,
            memsz: src.memsz as u64,
        };
        i += 1;
    }

    runtime
}

/// Install the runtime ABI into the locally linked substrate copy.
///
/// # Safety
/// Must be called during single-threaded rtld startup.
pub unsafe fn install_runtime_local(st: &RtldState, auxv: &AuxvInfo) {
    let runtime = build_runtime(st, auxv);
    unsafe { trona_runtime::runtime_install(&raw const runtime) };
}

// ---------------------------------------------------------------------------
// Loader runtime (TronaLoaderRuntimeV1)
// ---------------------------------------------------------------------------

/// rtld-owned static `TronaLoaderRuntimeV1`. Filled in once by
/// [`build_loader_runtime`] during startup; libc reads it indirectly via the
/// `trona_runtime::loader_runtime()` accessor after install.
static mut LOADER_RUNTIME: TronaLoaderRuntimeV1 = TronaLoaderRuntimeV1 {
    magic: 0,
    version: 0,
    flags: 0,
    dlfcn: RtldDlfcnV1 {
        dlopen: dlfcn_dlopen_placeholder,
        dlsym_from: dlfcn_dlsym_placeholder,
        dlclose: dlfcn_dlclose_placeholder,
        dladdr: dlfcn_dladdr_placeholder,
        dl_iterate_phdr: dlfcn_iter_placeholder,
        tls_addr: dlfcn_tls_addr_placeholder,
        tls_destroy: dlfcn_tls_destroy_placeholder,
    },
};

unsafe extern "C" fn dlfcn_dlopen_placeholder(
    _: *const u8,
    _: i32,
    _: *mut u8,
    _: usize,
) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn dlfcn_dlsym_placeholder(
    _: *mut u8,
    _: *const u8,
    _: usize,
    _: *mut u8,
    _: usize,
) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn dlfcn_dlclose_placeholder(_: *mut u8, _: *mut u8, _: usize) -> i32 {
    -1
}
unsafe extern "C" fn dlfcn_dladdr_placeholder(
    _: *const u8,
    _: *mut DlInfo,
    _: *mut u8,
    _: usize,
) -> i32 {
    0
}
unsafe extern "C" fn dlfcn_iter_placeholder(
    _: DlIterateCallback,
    _: *mut u8,
    _: *mut u8,
    _: usize,
) -> i32 {
    0
}
unsafe extern "C" fn dlfcn_tls_addr_placeholder(_: u64, _: u64, _: *mut u8, _: usize) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn dlfcn_tls_destroy_placeholder(_: u64, _: *mut u8, _: usize) {}

/// Populate and return a pointer to the rtld's static loader-runtime block.
/// Idempotent; subsequent calls overwrite with the same content.
pub fn build_loader_runtime() -> *mut TronaLoaderRuntimeV1 {
    let table = dlfcn::build_table();
    unsafe {
        let p = &raw mut LOADER_RUNTIME;
        (*p).magic = TronaLoaderRuntimeV1::MAGIC;
        (*p).version = TronaLoaderRuntimeV1::VERSION;
        (*p).flags = 0;
        (*p).dlfcn = table;
        p
    }
}
