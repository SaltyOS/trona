//! SPDX-License-Identifier: GPL-2.0-only
//! PE RTLD main — PE/COFF dependency loading, import resolution, handoff

use crate::common::elf::header as elf_header;
use crate::common::elf::types::page_align_up;
use crate::common::link_map::RtldState;
use crate::common::pe::export::{
    ImportSymbol, PeModuleImage, find_module, resolve_export, resolve_import,
};
use crate::common::pe::header;
use crate::common::pe::import;
use crate::common::pe::types::*;
use crate::rtld::cap;
use crate::rtld::io::{self, AuxvInfo};
use crate::rtld::mem;
use crate::rtld::runtime as rtld_runtime;
use crate::rtld::serial;
use crate::rtld::state;
use trona_kernel::core_types::{SALTYOS_IMAGE_KIND_PE, Win32ThreadPointerBlock};
use trona_kernel::invoke;
use trona_runtime::spawn::role_consts::{
    ROLE_INIT_CONTROL, ROLE_NAMESRV_CLIENT, ROLE_WIN32SRV_CLIENT,
};

const MAX_PE_MODULES: usize = trona_kernel::core_types::MAX_PE_TLS_MODULES;
const MAX_PE_MODULE_NAME: usize = 64;
const PE_TLS_RIGHTS: u32 = 0x3;

#[cfg(target_arch = "x86_64")]
type PeDllEntryFn = unsafe extern "win64" fn(*mut u8, u32, *mut u8) -> i32;
#[cfg(not(target_arch = "x86_64"))]
type PeDllEntryFn = unsafe extern "C" fn(*mut u8, u32, *mut u8) -> i32;

#[cfg(target_arch = "x86_64")]
type PeRuntimeInitFn = unsafe extern "win64" fn(u64, u64, u64, u64, u64, u64);
#[cfg(not(target_arch = "x86_64"))]
type PeRuntimeInitFn = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64);

#[derive(Clone, Copy)]
struct LoadedPeModule {
    name_len: usize,
    name: [u8; MAX_PE_MODULE_NAME],
    base: usize,
    size: usize,
    entry: usize,
    tls_raw_data: usize,
    tls_raw_size: usize,
    tls_index: u32,
    imports_resolved: bool,
    initializing: bool,
    initialized: bool,
}

impl LoadedPeModule {
    const fn zeroed() -> Self {
        Self {
            name_len: 0,
            name: [0; MAX_PE_MODULE_NAME],
            base: 0,
            size: 0,
            entry: 0,
            tls_raw_data: 0,
            tls_raw_size: 0,
            tls_index: 0,
            imports_resolved: false,
            initializing: false,
            initialized: false,
        }
    }

    fn set_name(&mut self, value: &[u8]) {
        let len = core::cmp::min(value.len(), MAX_PE_MODULE_NAME);
        self.name_len = len;
        let mut i = 0usize;
        while i < len {
            self.name[i] = value[i];
            i += 1;
        }
        while i < MAX_PE_MODULE_NAME {
            self.name[i] = 0;
            i += 1;
        }
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn as_image(&self) -> PeModuleImage<'_> {
        PeModuleImage {
            name: self.name_bytes(),
            base: self.base,
            size: self.size,
        }
    }
}

struct LoadedPeModules {
    count: usize,
    modules: [LoadedPeModule; MAX_PE_MODULES],
    tls_vector: usize,
    tls_vector_len: usize,
}

impl LoadedPeModules {
    const fn zeroed() -> Self {
        Self {
            count: 0,
            modules: [LoadedPeModule::zeroed(); MAX_PE_MODULES],
            tls_vector: 0,
            tls_vector_len: 0,
        }
    }

    fn push(&mut self, name: &[u8], base: usize, size: usize, entry: usize) -> usize {
        if self.count >= MAX_PE_MODULES {
            serial::fatal("too many PE modules");
        }
        let idx = self.count;
        self.modules[idx].set_name(name);
        self.modules[idx].base = base;
        self.modules[idx].size = size;
        self.modules[idx].entry = entry;
        self.modules[idx].tls_raw_data = 0;
        self.modules[idx].tls_raw_size = 0;
        self.modules[idx].tls_index = 0;
        self.modules[idx].imports_resolved = false;
        self.modules[idx].initializing = false;
        self.modules[idx].initialized = false;
        self.count += 1;
        idx
    }

    fn mark_imports_resolved(&mut self, idx: usize) {
        self.modules[idx].imports_resolved = true;
    }

    fn mark_initialized(&mut self, idx: usize) {
        self.modules[idx].initializing = false;
        self.modules[idx].initialized = true;
    }
}

/// PE RTLD entry path after unified dispatch.
///
/// The PE main executable is already mapped by the spawner. Every dependent DLL
/// is discovered and loaded by RTLD itself from the boot archive.
///
/// # Safety
/// `sp` must point to the initial stack.
pub unsafe fn run(sp: *const usize) -> usize {
    let stack = unsafe { io::parse_stack(sp) };
    let auxv = unsafe { io::parse_auxv(stack.auxv) };

    serial::print("[ldtrona-pe] starting\n");

    let st = unsafe { state::get_state() };
    unsafe { rtld_runtime::setup_rtld_object(&mut st.objects[0], &auxv) };
    st.count = 1;
    unsafe { rtld_runtime::init_state_from_auxv(st, &auxv) };
    unsafe { init_shared_lib_window(st, &auxv) };

    if auxv.main_image.kind != SALTYOS_IMAGE_KIND_PE {
        serial::fatal("startup main image is not PE");
    }
    if auxv.main_image.base == 0 || auxv.main_image.size == 0 {
        serial::fatal("missing PE main image metadata");
    }

    let main_base = auxv.main_image.base as usize;
    let main_size = auxv.main_image.size as usize;
    let main_pe = match unsafe { header::validate(main_base as *const u8, main_size) } {
        Ok(h) => h,
        Err(_) => serial::fatal("invalid PE headers"),
    };

    let mut modules = LoadedPeModules::zeroed();
    unsafe { seed_preloaded_modules(&mut modules, &auxv) };

    if let Some(import_dir) =
        unsafe { main_pe.data_directory(main_base as *const u8, IMAGE_DIRECTORY_ENTRY_IMPORT) }
    {
        unsafe {
            resolve_imports(
                main_base,
                import_dir.virtual_address,
                import_dir.size,
                &mut modules,
                st,
                &auxv,
            );
        }
    }
    if let Some(delay_dir) = unsafe {
        main_pe.data_directory(main_base as *const u8, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
    } {
        unsafe {
            resolve_delay_imports(
                main_base,
                delay_dir.virtual_address,
                delay_dir.size,
                &mut modules,
                st,
                &auxv,
            );
        }
    }

    unsafe { setup_process_tls_model(&mut modules, main_base, main_size, st) };
    unsafe { seed_module_tls_slots(&mut modules, st) };
    unsafe { state::publish_exports() };
    unsafe { rtld_runtime::install_runtime_local(st, &auxv) };
    // No post-load reprotection: the main image and every preloaded module were
    // mapped run-by-run with their final protections (text R-X, data R-W, the
    // IAT carved R-W), so W^X already holds and import resolution above wrote
    // into writable carve pages. Runtime-loaded modules are placed the same way.
    unsafe { init_builtin_modules(&modules, &auxv) };
    unsafe { initialize_modules(&mut modules, st) };
    unsafe { run_tls_callbacks(main_base, main_size) };

    let entry = if auxv.at_entry != 0 {
        auxv.at_entry
    } else if auxv.main_image.entry != 0 {
        auxv.main_image.entry as usize
    } else {
        main_base + main_pe.opt.address_of_entry_point as usize
    };

    serial::print("[ldtrona-pe] handoff to entry ");
    serial::print_hex(entry as u64);
    serial::putchar(b'\n');

    entry
}

unsafe fn init_shared_lib_window(st: &mut RtldState, auxv: &AuxvInfo) {
    if auxv.dso_window_base != 0 {
        st.lib_load_addr = auxv.dso_window_base;
        st.lib_load_limit = auxv.dso_window_base.saturating_add(auxv.dso_window_size);
        return;
    }

    let rtld_end = object_load_end(&st.objects[0]);
    let main_end = (auxv.main_image.base as usize)
        .saturating_add(page_align_up(auxv.main_image.size as usize));
    st.lib_load_addr = page_align_up(core::cmp::max(main_end, rtld_end).saturating_add(0x1000));
    st.lib_load_limit = 0;
}

fn object_load_end(lm: &crate::common::link_map::LinkMap) -> usize {
    if lm.phdr.is_null() || lm.phnum == 0 {
        return lm.entry;
    }
    let phdrs = unsafe { core::slice::from_raw_parts(lm.phdr, lm.phnum as usize) };
    if let Some((_, hi)) = elf_header::load_span(phdrs) {
        lm.base + hi as usize
    } else {
        lm.entry
    }
}

unsafe fn seed_preloaded_modules(modules: &mut LoadedPeModules, auxv: &AuxvInfo) {
    for mapped in auxv.mapped_images() {
        if mapped.image.kind != SALTYOS_IMAGE_KIND_PE {
            continue;
        }
        let name = mapped.name_bytes();
        if find_loaded_module_idx(modules, name).is_some() {
            continue;
        }
        if mapped.image.base == 0 || mapped.image.size == 0 {
            serial::fatal("invalid preloaded PE image metadata");
        }
        let _ = modules.push(
            name,
            mapped.image.base as usize,
            mapped.image.size as usize,
            mapped.image.entry as usize,
        );
        serial::print("[ldtrona-pe] loaded: ");
        serial::puts(name);
        serial::print(" @ ");
        serial::print_hex(mapped.image.base);
        serial::putchar(b'\n');
    }
}

unsafe fn resolve_imports(
    image_base: usize,
    import_rva: u32,
    import_size: u32,
    modules: &mut LoadedPeModules,
    st: &mut RtldState,
    auxv: &AuxvInfo,
) {
    let iter = unsafe { import::iter_import_descriptors(image_base, import_rva, import_size) };

    for entry in iter {
        let dll_name = unsafe { entry.dll_name() };
        let _ = unsafe { ensure_module_loaded(modules, st, auxv, dll_name) };

        serial::print("[ldtrona-pe] import: ");
        serial::puts(dll_name);
        serial::putchar(b'\n');

        let ilt_rva = entry.lookup_table_rva();
        let iat = entry.iat_ptr();
        let mut idx = 0usize;

        loop {
            let ilt_entry = unsafe { *((image_base + ilt_rva as usize + idx * 8) as *const u64) };
            if ilt_entry == 0 {
                break;
            }

            let mut image_storage = [PeModuleImage {
                name: b"",
                base: 0,
                size: 0,
            }; MAX_PE_MODULES];
            let images = build_module_images(modules, &mut image_storage);

            let resolved = if import::is_ordinal(ilt_entry) {
                let ord = import::ordinal(ilt_entry);
                match resolve_import(images, dll_name, ImportSymbol::Ordinal(ord)) {
                    Some(addr) => addr as u64,
                    None => {
                        serial::print("[ldtrona-pe] unresolved ordinal import ");
                        serial::print_hex(ord as u64);
                        serial::print(" from ");
                        serial::puts(dll_name);
                        serial::putchar(b'\n');
                        serial::fatal("PE ordinal import resolution failed");
                    }
                }
            } else {
                let rva = import::hint_name_rva(ilt_entry);
                let name = unsafe { import::hint_name_name(image_base, rva) };
                match resolve_import(images, dll_name, ImportSymbol::Name(name)) {
                    Some(addr) => addr as u64,
                    None => {
                        serial::print("[ldtrona-pe] unresolved named import ");
                        serial::puts(name);
                        serial::print(" from ");
                        serial::puts(dll_name);
                        serial::putchar(b'\n');
                        serial::fatal("PE named import resolution failed");
                    }
                }
            };

            unsafe { *iat.add(idx) = resolved };
            idx += 1;
        }
    }
}

unsafe fn ensure_module_loaded(
    modules: &mut LoadedPeModules,
    st: &mut RtldState,
    auxv: &AuxvInfo,
    dll_name: &[u8],
) -> usize {
    if let Some(idx) = find_loaded_module_idx(modules, dll_name) {
        if modules.modules[idx].imports_resolved {
            return idx;
        }

        let base = modules.modules[idx].base;
        let size = modules.modules[idx].size;
        let pe = match unsafe { header::validate(base as *const u8, size) } {
            Ok(h) => h,
            Err(_) => serial::fatal("loaded PE DLL is invalid"),
        };

        if let Some(import_dir) =
            unsafe { pe.data_directory(base as *const u8, IMAGE_DIRECTORY_ENTRY_IMPORT) }
        {
            unsafe {
                resolve_imports(
                    base,
                    import_dir.virtual_address,
                    import_dir.size,
                    modules,
                    st,
                    auxv,
                );
            }
        }
        if let Some(delay_dir) =
            unsafe { pe.data_directory(base as *const u8, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) }
        {
            unsafe {
                resolve_delay_imports(
                    base,
                    delay_dir.virtual_address,
                    delay_dir.size,
                    modules,
                    st,
                    auxv,
                );
            }
        }

        modules.mark_imports_resolved(idx);
        return idx;
    }

    serial::print("[ldtrona-pe] missing preloaded DLL ");
    serial::puts(dll_name);
    serial::putchar(b'\n');
    serial::fatal("PE DLL not preloaded");
}

fn reserve_space(st: &mut RtldState, image_size: usize, rights: u32) -> usize {
    let load_addr = st.lib_load_addr;
    if load_addr == 0 {
        serial::fatal("missing shared-library window");
    }

    let next_addr = load_addr.saturating_add(page_align_up(image_size));
    if st.lib_load_limit != 0 && next_addr > st.lib_load_limit {
        serial::fatal("shared-library window exhausted");
    }

    let num_pages = mem::pages_for(image_size);
    if st.next_untyped_slot == 0 || st.next_untyped_slot >= st.untyped_limit {
        serial::fatal("rtld untyped window exhausted");
    }
    if st.next_free_slot == 0
        || st.next_free_slot.saturating_add(num_pages as u32) > st.frame_slot_limit
    {
        serial::fatal("rtld frame slot window exhausted");
    }

    let err = unsafe {
        cap::alloc_and_map_range(
            &mut st.next_untyped_slot,
            st.untyped_limit,
            st.next_free_slot,
            load_addr,
            num_pages,
            rights,
        )
    };
    if err != 0 {
        serial::fatal_trona("failed to map PE DLL", err);
    }

    st.next_free_slot += num_pages as u32;
    st.lib_load_addr = next_addr;
    load_addr
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0usize;
    while i < a.len() {
        if fold_ascii(a[i]) != fold_ascii(b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

const fn fold_ascii(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { b + 32 } else { b }
}

fn find_loaded_module_idx(modules: &LoadedPeModules, dll_name: &[u8]) -> Option<usize> {
    let dll_name = module_basename(dll_name);
    let mut idx = 0usize;
    while idx < modules.count {
        if ascii_eq_ignore_case(module_basename(modules.modules[idx].name_bytes()), dll_name) {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

fn module_basename(name: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut i = 0usize;
    while i < name.len() {
        if name[i] == b'/' || name[i] == b'\\' {
            start = i + 1;
        }
        i += 1;
    }
    &name[start..]
}

fn build_module_images<'a>(
    modules: &'a LoadedPeModules,
    out: &'a mut [PeModuleImage<'a>; MAX_PE_MODULES],
) -> &'a [PeModuleImage<'a>] {
    let mut idx = 0usize;
    while idx < modules.count {
        out[idx] = modules.modules[idx].as_image();
        idx += 1;
    }
    &out[..modules.count]
}

unsafe fn setup_process_tls_model(
    modules: &mut LoadedPeModules,
    main_base: usize,
    main_size: usize,
    st: &mut RtldState,
) {
    if !unsafe { process_has_tls(main_base, main_size, modules) } {
        return;
    }

    let tls_vector_len = modules.count.saturating_add(1);
    let tls_vector_bytes = tls_vector_len * core::mem::size_of::<usize>();
    let tls_vector = reserve_space(st, tls_vector_bytes.max(1), PE_TLS_RIGHTS);
    unsafe {
        mem::memzero(
            tls_vector as *mut u8,
            page_align_up(tls_vector_bytes.max(1)),
        )
    };

    let teb = reserve_space(
        st,
        core::mem::size_of::<Win32ThreadPointerBlock>(),
        PE_TLS_RIGHTS,
    );
    let teb_ptr = teb as *mut Win32ThreadPointerBlock;
    unsafe { *teb_ptr = Win32ThreadPointerBlock::zeroed() };
    unsafe {
        (*teb_ptr).thread_local_storage_pointer = tls_vector as *mut *mut u8;
        (*teb_ptr).self_ptr = teb_ptr;
        (*teb_ptr).tls_vector_len = tls_vector_len as u64;
    }

    modules.tls_vector = tls_vector;
    modules.tls_vector_len = tls_vector_len;
    st.pe_abi_tp = teb;
    st.pe_tls_vector_len = tls_vector_len;

    let err = invoke::tcb_set_abi_tp(
        trona_kernel::core_types::CapRef::flat(uapi::KERNITE_CAP_SELF_TCB as u64),
        teb as u64,
    );
    if err != 0 {
        serial::fatal("failed to install PE ABI thread pointer");
    }

    unsafe { setup_main_tls(modules, main_base, main_size, st) };
}

unsafe fn process_has_tls(main_base: usize, main_size: usize, modules: &LoadedPeModules) -> bool {
    if unsafe { image_has_tls(main_base, main_size) } {
        return true;
    }
    let mut idx = 0usize;
    while idx < modules.count {
        if unsafe { image_has_tls(modules.modules[idx].base, modules.modules[idx].size) } {
            return true;
        }
        idx += 1;
    }
    false
}

unsafe fn image_has_tls(image_base: usize, image_size: usize) -> bool {
    let pe = match unsafe { header::validate(image_base as *const u8, image_size) } {
        Ok(h) => h,
        Err(_) => serial::fatal("invalid PE image"),
    };
    unsafe { pe.data_directory(image_base as *const u8, IMAGE_DIRECTORY_ENTRY_TLS) }.is_some()
}

unsafe fn write_tls_vector_entry(modules: &LoadedPeModules, index: usize, raw_base: usize) {
    if modules.tls_vector == 0 {
        serial::fatal("PE TLS vector missing");
    }
    if index >= modules.tls_vector_len {
        serial::fatal("PE TLS vector overflow");
    }
    unsafe {
        *((modules.tls_vector as *mut usize).add(index)) = raw_base;
    }
}

unsafe fn publish_pe_tls_module(
    st: &mut RtldState,
    tls_index: u32,
    template_addr: usize,
    filesz: usize,
    memsz: usize,
) {
    let mut i = 0usize;
    while i < st.pe_tls_module_count {
        if st.pe_tls_modules[i].tls_index == tls_index {
            st.pe_tls_modules[i].template_addr = template_addr;
            st.pe_tls_modules[i].filesz = filesz;
            st.pe_tls_modules[i].memsz = memsz;
            return;
        }
        i += 1;
    }

    if st.pe_tls_module_count >= trona_kernel::core_types::MAX_PE_TLS_MODULES {
        serial::fatal("too many PE TLS modules");
    }
    st.pe_tls_modules[st.pe_tls_module_count] = crate::common::link_map::PeTlsModuleState {
        tls_index,
        reserved: 0,
        template_addr,
        filesz,
        memsz,
    };
    st.pe_tls_module_count += 1;
}

unsafe fn initialize_modules(modules: &mut LoadedPeModules, st: &mut RtldState) {
    let mut idx = 0usize;
    while idx < modules.count {
        unsafe { initialize_module(modules, idx, st) };
        idx += 1;
    }
}

unsafe fn seed_module_tls_slots(modules: &mut LoadedPeModules, st: &mut RtldState) {
    let mut idx = 0usize;
    while idx < modules.count {
        let tls_index = idx.saturating_add(1) as u32;
        unsafe { setup_module_tls(modules, idx, tls_index, st) };
        idx += 1;
    }
}

unsafe fn initialize_module(modules: &mut LoadedPeModules, idx: usize, st: &mut RtldState) {
    if modules.modules[idx].initialized {
        return;
    }
    if modules.modules[idx].initializing {
        return;
    }
    modules.modules[idx].initializing = true;

    let base = modules.modules[idx].base;
    let size = modules.modules[idx].size;
    let pe = match unsafe { header::validate(base as *const u8, size) } {
        Ok(h) => h,
        Err(_) => serial::fatal("loaded PE DLL is invalid"),
    };

    if let Some(import_dir) =
        unsafe { pe.data_directory(base as *const u8, IMAGE_DIRECTORY_ENTRY_IMPORT) }
    {
        let iter = unsafe {
            import::iter_import_descriptors(base, import_dir.virtual_address, import_dir.size)
        };
        for entry in iter {
            let dll_name = unsafe { entry.dll_name() };
            let dep_idx = match find_loaded_module_idx(modules, dll_name) {
                Some(dep_idx) => dep_idx,
                None => {
                    serial::print("[ldtrona-pe] missing loaded dependency ");
                    serial::puts(dll_name);
                    serial::putchar(b'\n');
                    serial::fatal("PE module graph is inconsistent");
                }
            };
            unsafe { initialize_module(modules, dep_idx, st) };
        }
    }
    if let Some(delay_dir) =
        unsafe { pe.data_directory(base as *const u8, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) }
    {
        let mut offset = 0usize;
        while offset + core::mem::size_of::<DelayImportDescriptor>() <= delay_dir.size as usize {
            let desc = unsafe {
                &*((base + delay_dir.virtual_address as usize + offset)
                    as *const DelayImportDescriptor)
            };
            if desc.name == 0
                && desc.delay_import_address_table == 0
                && desc.delay_import_name_table == 0
            {
                break;
            }
            let dll_name_ptr = delay_ptr(base, desc.attributes, desc.name);
            let dll_name = unsafe { c_string(dll_name_ptr as *const u8) };
            let dep_idx = match find_loaded_module_idx(modules, dll_name) {
                Some(dep_idx) => dep_idx,
                None => {
                    serial::print("[ldtrona-pe] missing loaded delay dependency ");
                    serial::puts(dll_name);
                    serial::putchar(b'\n');
                    serial::fatal("PE module graph is inconsistent");
                }
            };
            unsafe { initialize_module(modules, dep_idx, st) };
            offset += core::mem::size_of::<DelayImportDescriptor>();
        }
    }

    let tls_index = idx.saturating_add(1) as u32;
    unsafe { setup_module_tls(modules, idx, tls_index, st) };
    unsafe { run_tls_callbacks(base, size) };
    unsafe {
        call_module_entry(
            modules.modules[idx].entry,
            base,
            modules.modules[idx].name_bytes(),
        )
    };
    modules.mark_initialized(idx);
}

unsafe fn setup_main_tls(
    modules: &LoadedPeModules,
    image_base: usize,
    image_size: usize,
    st: &mut RtldState,
) {
    let pe = match unsafe { header::validate(image_base as *const u8, image_size) } {
        Ok(h) => h,
        Err(_) => serial::fatal("invalid PE image"),
    };
    let Some(tls_dir) =
        (unsafe { pe.data_directory(image_base as *const u8, IMAGE_DIRECTORY_ENTRY_TLS) })
    else {
        return;
    };

    let tls =
        unsafe { &mut *((image_base + tls_dir.virtual_address as usize) as *mut TlsDirectory64) };
    let raw_start = tls.start_address_of_raw_data as usize;
    let raw_end = tls.end_address_of_raw_data as usize;
    let raw_size = raw_end
        .saturating_sub(raw_start)
        .saturating_add(tls.size_of_zero_fill as usize);
    if raw_size == 0 {
        if tls.address_of_index != 0 {
            unsafe { *(tls.address_of_index as *mut u32) = 0 };
        }
        unsafe {
            publish_pe_tls_module(
                st,
                0,
                raw_start,
                raw_end.saturating_sub(raw_start),
                raw_size,
            )
        };
        unsafe { write_tls_vector_entry(modules, 0, 0) };
        return;
    }

    let raw_base = unsafe { allocate_tls_raw_data(st, raw_size) };
    if raw_end > raw_start {
        unsafe {
            mem::memcpy(
                raw_base as *mut u8,
                raw_start as *const u8,
                raw_end - raw_start,
            );
        }
    }
    if tls.size_of_zero_fill != 0 {
        unsafe {
            mem::memzero(
                (raw_base + raw_end.saturating_sub(raw_start)) as *mut u8,
                tls.size_of_zero_fill as usize,
            );
        }
    }
    if tls.address_of_index != 0 {
        unsafe { *(tls.address_of_index as *mut u32) = 0 };
    }
    unsafe {
        publish_pe_tls_module(
            st,
            0,
            raw_start,
            raw_end.saturating_sub(raw_start),
            raw_size,
        )
    };
    unsafe { write_tls_vector_entry(modules, 0, raw_base) };
}

unsafe fn setup_module_tls(
    modules: &mut LoadedPeModules,
    idx: usize,
    tls_index: u32,
    st: &mut RtldState,
) {
    if modules.modules[idx].tls_raw_data != 0 || modules.modules[idx].tls_index != 0 {
        return;
    }

    let base = modules.modules[idx].base;
    let size = modules.modules[idx].size;
    let pe = match unsafe { header::validate(base as *const u8, size) } {
        Ok(h) => h,
        Err(_) => serial::fatal("loaded PE DLL is invalid"),
    };
    let Some(tls_dir) =
        (unsafe { pe.data_directory(base as *const u8, IMAGE_DIRECTORY_ENTRY_TLS) })
    else {
        return;
    };

    let tls = unsafe { &mut *((base + tls_dir.virtual_address as usize) as *mut TlsDirectory64) };
    let raw_start = tls.start_address_of_raw_data as usize;
    let raw_end = tls.end_address_of_raw_data as usize;
    let raw_size = raw_end
        .saturating_sub(raw_start)
        .saturating_add(tls.size_of_zero_fill as usize);
    if raw_size == 0 {
        if tls.address_of_index != 0 {
            unsafe { *(tls.address_of_index as *mut u32) = tls_index };
        }
        modules.modules[idx].tls_index = tls_index;
        unsafe {
            publish_pe_tls_module(
                st,
                tls_index,
                raw_start,
                raw_end.saturating_sub(raw_start),
                raw_size,
            )
        };
        unsafe { write_tls_vector_entry(modules, tls_index as usize, 0) };
        return;
    }

    let raw_base = unsafe { allocate_tls_raw_data(st, raw_size) };
    if raw_end > raw_start {
        unsafe {
            mem::memcpy(
                raw_base as *mut u8,
                raw_start as *const u8,
                raw_end - raw_start,
            );
        }
    }
    if tls.size_of_zero_fill != 0 {
        unsafe {
            mem::memzero(
                (raw_base + raw_end.saturating_sub(raw_start)) as *mut u8,
                tls.size_of_zero_fill as usize,
            );
        }
    }
    if tls.address_of_index != 0 {
        unsafe { *(tls.address_of_index as *mut u32) = tls_index };
    }
    modules.modules[idx].tls_raw_data = raw_base;
    modules.modules[idx].tls_raw_size = raw_size;
    modules.modules[idx].tls_index = tls_index;
    unsafe {
        publish_pe_tls_module(
            st,
            tls_index,
            raw_start,
            raw_end.saturating_sub(raw_start),
            raw_size,
        )
    };
    unsafe { write_tls_vector_entry(modules, tls_index as usize, raw_base) };
}

unsafe fn run_tls_callbacks(image_base: usize, image_size: usize) {
    let pe = match unsafe { header::validate(image_base as *const u8, image_size) } {
        Ok(h) => h,
        Err(_) => serial::fatal("invalid PE image"),
    };

    let Some(tls_dir) =
        (unsafe { pe.data_directory(image_base as *const u8, IMAGE_DIRECTORY_ENTRY_TLS) })
    else {
        return;
    };

    let tls =
        unsafe { &*((image_base + tls_dir.virtual_address as usize) as *const TlsDirectory64) };
    if tls.address_of_callbacks == 0 {
        return;
    }

    let mut callbacks = tls.address_of_callbacks as *const usize;
    while !callbacks.is_null() {
        let callback = unsafe { *callbacks };
        if callback == 0 {
            break;
        }
        let func: PeDllEntryFn = unsafe { core::mem::transmute(callback) };
        unsafe {
            func(
                image_base as *mut u8,
                DLL_PROCESS_ATTACH,
                core::ptr::null_mut(),
            )
        };
        callbacks = unsafe { callbacks.add(1) };
    }
}

unsafe fn resolve_delay_imports(
    image_base: usize,
    delay_rva: u32,
    delay_size: u32,
    modules: &mut LoadedPeModules,
    st: &mut RtldState,
    auxv: &AuxvInfo,
) {
    let mut offset = 0usize;
    while offset + core::mem::size_of::<DelayImportDescriptor>() <= delay_size as usize {
        let desc_ptr = (image_base + delay_rva as usize + offset) as *const DelayImportDescriptor;
        let desc = unsafe { &*desc_ptr };
        if desc.name == 0
            && desc.delay_import_address_table == 0
            && desc.delay_import_name_table == 0
        {
            break;
        }

        let dll_name_ptr = delay_ptr(image_base, desc.attributes, desc.name);
        let dll_name = unsafe { c_string(dll_name_ptr as *const u8) };
        let module_idx = unsafe { ensure_module_loaded(modules, st, auxv, dll_name) };
        if desc.module_handle != 0 {
            let module_handle_ptr =
                delay_ptr(image_base, desc.attributes, desc.module_handle) as *mut usize;
            unsafe { *module_handle_ptr = modules.modules[module_idx].base };
        }

        let ilt = if desc.delay_import_name_table != 0 {
            delay_ptr(image_base, desc.attributes, desc.delay_import_name_table) as *const u64
        } else {
            delay_ptr(image_base, desc.attributes, desc.delay_import_address_table) as *const u64
        };
        let iat =
            delay_ptr(image_base, desc.attributes, desc.delay_import_address_table) as *mut u64;

        let mut idx = 0usize;
        loop {
            let ilt_entry = unsafe { *ilt.add(idx) };
            if ilt_entry == 0 {
                break;
            }

            let mut image_storage = [PeModuleImage {
                name: b"",
                base: 0,
                size: 0,
            }; MAX_PE_MODULES];
            let images = build_module_images(modules, &mut image_storage);

            let resolved = if import::is_ordinal(ilt_entry) {
                let ord = import::ordinal(ilt_entry);
                match resolve_import(images, dll_name, ImportSymbol::Ordinal(ord)) {
                    Some(addr) => addr as u64,
                    None => {
                        serial::print("[ldtrona-pe] unresolved delay ordinal import ");
                        serial::print_hex(ord as u64);
                        serial::print(" from ");
                        serial::puts(dll_name);
                        serial::putchar(b'\n');
                        serial::fatal("PE delay ordinal import resolution failed");
                    }
                }
            } else {
                let hint_name_ptr = delay_thunk_ptr(image_base, desc.attributes, ilt_entry);
                let name = unsafe { c_string((hint_name_ptr + 2) as *const u8) };
                match resolve_import(images, dll_name, ImportSymbol::Name(name)) {
                    Some(addr) => addr as u64,
                    None => {
                        serial::print("[ldtrona-pe] unresolved delay named import ");
                        serial::puts(name);
                        serial::print(" from ");
                        serial::puts(dll_name);
                        serial::putchar(b'\n');
                        serial::fatal("PE delay named import resolution failed");
                    }
                }
            };

            unsafe { *iat.add(idx) = resolved };
            idx += 1;
        }

        offset += core::mem::size_of::<DelayImportDescriptor>();
    }
}

#[inline]
fn delay_ptr(image_base: usize, attributes: u32, value: u32) -> usize {
    if attributes & DELAY_IMPORT_ATTR_RVA != 0 {
        image_base + value as usize
    } else {
        value as usize
    }
}

#[inline]
fn delay_thunk_ptr(image_base: usize, attributes: u32, value: u64) -> usize {
    if attributes & DELAY_IMPORT_ATTR_RVA != 0 {
        image_base + value as usize
    } else {
        value as usize
    }
}

unsafe fn allocate_tls_raw_data(st: &mut RtldState, size: usize) -> usize {
    let alloc_size = page_align_up(size.max(1));
    let load_addr = reserve_space(st, alloc_size, PE_TLS_RIGHTS);
    unsafe { mem::memzero(load_addr as *mut u8, alloc_size) };
    load_addr
}

unsafe fn c_string(ptr: *const u8) -> &'static [u8] {
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

unsafe fn call_module_entry(entry: usize, image_base: usize, module_name: &[u8]) {
    if entry == 0 {
        return;
    }

    let func: PeDllEntryFn = unsafe { core::mem::transmute(entry) };
    let ok = unsafe {
        func(
            image_base as *mut u8,
            DLL_PROCESS_ATTACH,
            core::ptr::null_mut(),
        )
    };
    if ok == 0 {
        serial::print("[ldtrona-pe] module init failed: ");
        serial::puts(module_name);
        serial::putchar(b'\n');
        serial::fatal("PE module entry failed");
    }
}

struct BuiltinModuleInit {
    module_name: &'static [u8],
    symbol_name: &'static [u8],
    kind: BuiltinModuleInitKind,
}

enum BuiltinModuleInitKind {
    Kernel32Runtime,
}

const BUILTIN_MODULE_INITS: &[BuiltinModuleInit] = &[BuiltinModuleInit {
    module_name: b"kernel32.dll",
    symbol_name: b"kernel32_runtime_init",
    kind: BuiltinModuleInitKind::Kernel32Runtime,
}];

unsafe fn init_builtin_modules(modules: &LoadedPeModules, auxv: &AuxvInfo) {
    let mut image_storage = [PeModuleImage {
        name: b"",
        base: 0,
        size: 0,
    }; MAX_PE_MODULES];
    let images = build_module_images(modules, &mut image_storage);

    for init in BUILTIN_MODULE_INITS {
        let Some(module) = find_module(images, init.module_name) else {
            continue;
        };
        let entry = match resolve_export(images, module, ImportSymbol::Name(init.symbol_name)) {
            Some(addr) => addr,
            None => {
                serial::print("[ldtrona-pe] missing builtin init ");
                serial::puts(init.symbol_name);
                serial::print(" in ");
                serial::puts(init.module_name);
                serial::putchar(b'\n');
                serial::fatal("builtin PE module init missing");
            }
        };

        match init.kind {
            BuiltinModuleInitKind::Kernel32Runtime => {
                let func: PeRuntimeInitFn = unsafe { core::mem::transmute(entry) };
                let (cap_alloc_base, cap_alloc_limit) = match auxv.cspace_layout() {
                    Some(layout) => (layout.alloc_base, layout.alloc_limit),
                    None => (0, 0),
                };
                unsafe {
                    func(
                        auxv.ipc_buffer_vaddr as u64,
                        auxv.cap_slot(ROLE_WIN32SRV_CLIENT) as u64,
                        auxv.cap_slot(ROLE_INIT_CONTROL) as u64,
                        auxv.cap_slot(ROLE_NAMESRV_CLIENT) as u64,
                        cap_alloc_base,
                        cap_alloc_limit,
                    );
                }
            }
        }
    }
}
