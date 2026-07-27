//! SPDX-License-Identifier: GPL-2.0-only
//! ELF RTLD main — startup linker, dependency seed, runtime handoff.
//!
//! All per-object helpers (apply_dyn_info, relocate_object, install_got,
//! _dl_fixup, find_loaded_object, find_main_ehdr_from_at_phdr) live in
//! [`object`]. Symbol resolution lives in [`scope`]. dlfcn entries live in
//! [`dlfcn`].

use crate::common::elf::dynamic;
use crate::common::elf::header;
use crate::common::elf::tls;
use crate::common::elf::types::*;
use crate::common::link_map::{LinkMap, RTLD_MAX_OBJECTS, RtldState, link_flags};
use crate::rtld::elf::dlfcn;
use crate::rtld::elf::object;
use crate::rtld::io::{self, AuxvInfo};
use crate::rtld::runtime as rtld_runtime;
use crate::rtld::serial;
use crate::rtld::state;
use trona_kernel::core_types::{
    RtldDlfcnV1, SALTYOS_IMAGE_KIND_ELF, SaltyOSMappedImageV1, TronaLoaderRuntimeV1, TronaRuntimeV1,
};

/// ELF RTLD entry path after unified dispatch.
///
/// # Safety
/// `sp` must point to the initial stack (argc/argv/envp/auxv layout).
pub unsafe fn run(sp: *const usize) -> usize {
    let stack = unsafe { io::parse_stack(sp) };
    let auxv = unsafe { io::parse_auxv(stack.auxv) };

    serial::print("[ldtrona-elf] starting\n");

    let st = unsafe { state::get_state() };

    // Set up RTLD (slot 0) and main executable (slot 1).
    unsafe { rtld_runtime::setup_rtld_object(&mut st.objects[0], &auxv) };
    if auxv.at_phdr == 0 || auxv.at_phnum == 0 {
        serial::fatal("missing main program headers");
    }
    unsafe { setup_main_object(&mut st.objects[1], &auxv) };
    st.objects[0].set_flag(link_flags::STARTUP);
    st.objects[1].set_flag(link_flags::STARTUP);
    st.count = 2;

    unsafe { rtld_runtime::init_state_from_auxv(st, &auxv) };
    unsafe { init_shared_lib_window(st, &auxv) };
    unsafe { seed_preloaded_objects(st, &auxv) };
    unsafe { resolve_startup_dependencies(st) };

    // Relocate every seed object that hasn't been processed yet.
    for i in 0..st.count {
        if !st.objects[i].has_flag(link_flags::RELOCATED) {
            unsafe { object::relocate_object(st, i) };
        }
    }

    // Install GOT[1]/GOT[2] for lazy binding.
    for i in 0..st.count {
        unsafe { object::install_got_entries(&mut st.objects[i]) };
    }

    // ldsrv-resolved objects are mapped run-by-run with their final
    // protections (text R-X, data R-W, rodata R--), so there is no
    // writable-then-executable transition to undo here — only PT_GNU_RELRO
    // narrowing remains, below.

    // PT_GNU_RELRO may cover .got/.got.plt pages after page alignment. Apply
    // it only after the loader has finished patching GOT entries.
    for i in 0..st.count {
        unsafe { apply_relro(&st.objects[i]) };
    }

    // Set up TLS after the full object graph is known.
    unsafe { setup_tls(st) };

    // Publish rtld-owned runtime state, then hand it to libtrona/libc before
    // any constructors run.
    unsafe { state::publish_exports() };
    unsafe { rtld_runtime::install_runtime_local(st, &auxv) };
    unsafe { install_runtime_auxv(st, &auxv) };

    // Initialize DSOs in dependency-last order; the main executable's own
    // init arrays remain the C runtime's responsibility.
    unsafe { call_dso_inits(st) };

    serial::print("[ldtrona-elf] handoff to entry ");
    serial::print_hex(auxv.at_entry as u64);
    serial::putchar(b'\n');

    auxv.at_entry
}

/// Populates the main executable's link map from auxv info.
///
/// # Safety
/// The phdr must be mapped and valid.
unsafe fn setup_main_object(lm: &mut LinkMap, auxv: &AuxvInfo) {
    let phdr = auxv.at_phdr as *const Elf64Phdr;
    let phnum = auxv.at_phnum;
    let phdrs = unsafe { core::slice::from_raw_parts(phdr, phnum) };

    let runtime_phdr_vaddr = if let Some(phdr_ph) = header::find_phdr_phdr(phdrs) {
        phdr_ph.p_vaddr as usize
    } else if let Some(ehdr) =
        unsafe { object::find_main_ehdr_from_at_phdr(auxv.at_phdr, auxv.at_phent, auxv.at_phnum) }
    {
        ehdr.e_phoff as usize
    } else {
        serial::fatal("main program header fallback failed");
    };
    lm.base = auxv.at_phdr.saturating_sub(runtime_phdr_vaddr);
    lm.phdr = phdr;
    lm.phnum = phnum as u16;
    lm.entry = auxv.at_entry;
    lm.e_type = if lm.base != 0 { ET_DYN } else { ET_EXEC };
    lm.name = b"<main>\0".as_ptr();

    if let Some(dyn_ph) = header::find_dynamic_phdr(phdrs) {
        let dyn_ptr = (lm.base + dyn_ph.p_vaddr as usize) as *const Elf64Dyn;
        lm.dynamic = dyn_ptr;
        lm.dyn_info = unsafe { dynamic::parse_dynamic(dyn_ptr) };
        unsafe { object::apply_dyn_info(lm) };
    }

    if let Some(tls_ph) = header::find_tls_phdr(phdrs) {
        lm.tls_image = lm.base + tls_ph.p_vaddr as usize;
        lm.tls_filesz = tls_ph.p_filesz as usize;
        lm.tls_memsz = tls_ph.p_memsz as usize;
        lm.tls_align = tls_ph.p_align as usize;
    }
}

unsafe fn init_shared_lib_window(st: &mut RtldState, auxv: &AuxvInfo) {
    if auxv.dso_window_base != 0 {
        st.lib_load_addr = auxv.dso_window_base;
        st.lib_load_limit = auxv.dso_window_base.saturating_add(auxv.dso_window_size);
        return;
    }

    let main_end = object_load_end(&st.objects[1]);
    let rtld_end = object_load_end(&st.objects[0]);
    st.lib_load_addr = page_align_up(core::cmp::max(main_end, rtld_end).saturating_add(PAGE_SIZE));
    st.lib_load_limit = 0;
}

fn object_load_end(lm: &LinkMap) -> usize {
    if lm.phdr.is_null() || lm.phnum == 0 {
        return lm.entry;
    }
    let phdrs = unsafe { core::slice::from_raw_parts(lm.phdr, lm.phnum as usize) };
    if let Some((_, hi)) = header::load_span(phdrs) {
        lm.base + hi as usize
    } else {
        lm.entry
    }
}

unsafe fn seed_preloaded_objects(st: &mut RtldState, auxv: &AuxvInfo) {
    for mapped in auxv.mapped_images() {
        if mapped.image.kind != SALTYOS_IMAGE_KIND_ELF {
            continue;
        }
        let name = mapped.name_bytes();
        if object::find_loaded_object(st, name).is_some() {
            continue;
        }
        if st.count >= RTLD_MAX_OBJECTS {
            serial::fatal("too many shared objects");
        }
        let idx = st.count;
        unsafe { setup_preloaded_object(&mut st.objects[idx], mapped) };
        st.objects[idx].set_flag(link_flags::STARTUP);
        st.count = idx + 1;

        serial::print("[ldtrona-elf] loaded: ");
        serial::puts(name);
        serial::print(" @ ");
        serial::print_hex(mapped.image.base);
        serial::putchar(b'\n');
    }
}

unsafe fn setup_preloaded_object(lm: &mut LinkMap, mapped: &SaltyOSMappedImageV1) {
    let base_addr = mapped.image.base as usize;
    let image_size = mapped.image.size as usize;
    if base_addr == 0 || image_size == 0 {
        serial::fatal("invalid preloaded ELF image metadata");
    }

    let ehdr = match unsafe { header::validate_ehdr(base_addr as *const u8, image_size) } {
        Ok(e) => e,
        Err(_) => serial::fatal("invalid preloaded ELF image"),
    };
    let phdrs = match unsafe { header::phdr_slice(base_addr as *const u8, image_size, ehdr) } {
        Ok(p) => p,
        Err(_) => serial::fatal("invalid preloaded ELF phdrs"),
    };

    lm.base = base_addr;
    lm.name = mapped.name.as_ptr();
    lm.e_type = ehdr.e_type;
    lm.entry = if mapped.image.entry != 0 {
        mapped.image.entry as usize
    } else {
        lm.base + ehdr.e_entry as usize
    };
    lm.phdr = (base_addr + ehdr.e_phoff as usize) as *const Elf64Phdr;
    lm.phnum = ehdr.e_phnum;
    lm.map_start = base_addr;
    lm.map_end = base_addr + image_size;

    if let Some(dyn_ph) = header::find_dynamic_phdr(phdrs) {
        let dyn_ptr = (lm.base + dyn_ph.p_vaddr as usize) as *const Elf64Dyn;
        lm.dynamic = dyn_ptr;
        lm.dyn_info = unsafe { dynamic::parse_dynamic(dyn_ptr) };
        unsafe { object::apply_dyn_info(lm) };
        if lm.dyn_info.soname != 0 && !lm.strtab.is_null() {
            lm.soname = unsafe { lm.strtab.add(lm.dyn_info.soname as usize) };
        }
    }

    if let Some(tls_ph) = header::find_tls_phdr(phdrs) {
        lm.tls_image = lm.base + tls_ph.p_vaddr as usize;
        lm.tls_filesz = tls_ph.p_filesz as usize;
        lm.tls_memsz = tls_ph.p_memsz as usize;
        lm.tls_align = tls_ph.p_align as usize;
    }
}

/// Resolve every startup object's `DT_NEEDED` graph. Dependencies init
/// pre-mapped (service spawn, from the initrd) are already in `st.objects`
/// and skipped; any not yet present (path-exec, where init mapped only the
/// main image and the interpreter) are loaded from the filesystem via vfs
/// in this process's own context and appended to `st.objects`, so the
/// startup relocation / GOT / TLS / init loops cover them. The outer loop
/// revisits newly-appended objects, making the resolution transitive.
unsafe fn resolve_startup_dependencies(st: &mut RtldState) {
    let mut idx = 1usize;
    while idx < st.count {
        let dyn_ptr = st.objects[idx].dynamic;
        if dyn_ptr.is_null() {
            idx += 1;
            continue;
        }

        let needed_iter = unsafe { dynamic::NeededIter::new(dyn_ptr) };
        let strtab = st.objects[idx].strtab;
        for offset in needed_iter {
            let name = unsafe { strtab.add(offset as usize) };
            let mut name_len = 0usize;
            while unsafe { *name.add(name_len) } != 0 {
                name_len += 1;
            }
            let name_slice = unsafe { core::slice::from_raw_parts(name, name_len) };
            if object::find_loaded_object(st, name_slice).is_some() {
                continue;
            }

            // Not pre-mapped (path-exec): resolve it through ldsrv, which owns
            // the library namespace and search order. The DT_NEEDED string is a
            // soname; the linker no longer searches the filesystem itself.
            if st.count >= RTLD_MAX_OBJECTS {
                serial::fatal("too many shared objects");
            }
            let lm = match unsafe { object::load_object_into(st, name) } {
                Ok(lm) => lm,
                Err(err) => {
                    serial::print("[ldtrona-elf] failed to load DT_NEEDED: ");
                    serial::puts(name_slice);
                    serial::print(" stage=");
                    serial::puts(object_load_error_stage(err));
                    serial::putchar(b'\n');
                    serial::fatal("ELF dependency load failed");
                }
            };
            let dst = st.count;
            st.objects[dst] = lm;
            st.objects[dst].set_flag(link_flags::STARTUP);
            st.count = dst + 1;

            serial::print("[ldtrona-elf] loaded from vfs: ");
            serial::puts(name_slice);
            serial::putchar(b'\n');
        }
        idx += 1;
    }
}

fn object_load_error_stage(err: object::LoadError) -> &'static [u8] {
    match err {
        object::LoadError::ArenaMmapFailed => b"arena-mmap",
        object::LoadError::OpenFailed => b"ldsrv-resolve",
        object::LoadError::StatFailed => b"stat",
        object::LoadError::ReadFailed => b"read",
        object::LoadError::NotElf => b"elf-header",
        object::LoadError::UnsupportedClass => b"elf-class",
        object::LoadError::UnsupportedMachine => b"elf-machine",
        object::LoadError::NoLoadable => b"no-pt-load",
        object::LoadError::DsoWindowExhausted => b"dso-window",
        object::LoadError::RunPlanFailed => b"run-plan",
        object::LoadError::ImageReserveFailed => b"image-reserve",
        object::LoadError::ImageAliasFailed => b"image-alias",
        object::LoadError::ImageMapRunFailed => b"image-map-run",
        object::LoadError::MmapFailed => b"mmap",
        object::LoadError::Mprotect => b"mprotect",
        object::LoadError::OutOfArena => b"rtld-arena",
        object::LoadError::DependencyMissing => b"dependency",
        object::LoadError::RelocationFailed => b"relocation",
    }
}

unsafe fn apply_relro(lm: &LinkMap) {
    if lm.phdr.is_null() || lm.phnum == 0 {
        return;
    }
    let phdrs = unsafe { core::slice::from_raw_parts(lm.phdr, lm.phnum as usize) };
    for ph in phdrs {
        if ph.p_type != PT_GNU_RELRO || ph.p_memsz == 0 {
            continue;
        }
        // Protect only whole pages that lie *strictly inside* the RELRO
        // region: round the start UP and the end DOWN. PT_GNU_RELRO is not
        // page-aligned here, so a page straddling either edge also holds
        // adjacent mutable `.data`/`.bss`; rounding outward would map that
        // data read-only and a later write to it faults. This mirrors the
        // glibc/musl rule of never extending the protection past the RELRO
        // bounds. A sub-page RELRO is simply left unprotected (`end <= start`).
        let start = lm.base.saturating_add(page_align_up(ph.p_vaddr as usize));
        let end = lm.base.saturating_add(page_align_down(
            (ph.p_vaddr as usize).saturating_add(ph.p_memsz as usize),
        ));
        if end <= start {
            continue;
        }
        let count = (end - start) / PAGE_SIZE;
        let (err, protected) = trona_kernel::invoke::vspace_protect_range(
            trona_kernel::core_types::CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64),
            start as u64,
            count as u64,
            uapi::KERNITE_PAGE_FLAG_USER as u64,
        );
        if err != 0 || protected != count as u64 {
            serial::fatal("failed to protect PT_GNU_RELRO");
        }
    }
}

/// Sets up static TLS for all objects with PT_TLS.
///
/// # Safety
/// TLS module state must not be concurrently accessed.
unsafe fn setup_tls(st: &mut RtldState) {
    for i in 0..st.count {
        let lm = &st.objects[i];
        if lm.tls_memsz == 0 {
            continue;
        }
        if let Some(mod_id) = tls::tls_alloc_module(
            &mut st.tls_layout,
            &mut st.tls_modules,
            lm.tls_memsz,
            lm.tls_filesz,
            lm.tls_align,
            lm.tls_image,
        ) {
            st.objects[i].tls_mod_id = mod_id;
        }
    }
    // Seed the dynamic-TLS module-ID counter to start past every static slot.
    st.next_dynamic_tls_module_id.store(
        crate::common::elf::tls::DYNAMIC_TLS_MODULE_BASE,
        ::core::sync::atomic::Ordering::Release,
    );
}

unsafe fn call_dso_inits(st: &mut RtldState) {
    let mut idx = st.count;
    while idx > 2 {
        idx -= 1;
        if !st.objects[idx].has_flag(link_flags::INIT_DONE) {
            unsafe { object::run_init(&mut st.objects[idx]) };
        }
    }
}

/// Installs runtime metadata by calling libtrona's `trona_runtime_install`
/// (TronaRuntimeV1) and then `trona_loader_runtime_install`
/// (TronaLoaderRuntimeV1). Both must be reachable in already-relocated
/// loaded objects.
///
/// # Safety
/// All objects must be relocated before this call.
unsafe fn install_runtime_auxv(st: &RtldState, auxv: &AuxvInfo) {
    let runtime = rtld_runtime::build_runtime(st, auxv);
    let installer = find_extern_symbol(st, b"trona_runtime_install").unwrap_or_else(|| {
        serial::fatal("missing trona_runtime_install");
    });
    let f: unsafe extern "C" fn(*const TronaRuntimeV1) = unsafe { core::mem::transmute(installer) };
    serial::print("[ldtrona-elf] startup via trona_runtime_install\n");
    unsafe { f(&raw const runtime) };

    // Loader runtime: rtld owns the static TronaLoaderRuntimeV1 and hands
    // libtrona a pointer.
    let loader_rt = rtld_runtime::build_loader_runtime();
    let loader_installer = match find_extern_symbol(st, b"trona_loader_runtime_install") {
        Some(addr) => addr,
        None => {
            serial::print("[ldtrona-elf] WARN: trona_loader_runtime_install missing\n");
            return;
        }
    };
    let lf: unsafe extern "C" fn(*const TronaLoaderRuntimeV1) -> i32 =
        unsafe { core::mem::transmute(loader_installer) };
    let rc = unsafe { lf(loader_rt as *const TronaLoaderRuntimeV1) };
    if rc != 0 {
        serial::print("[ldtrona-elf] trona_loader_runtime_install failed\n");
    }
}

/// Look up `name` as an exported symbol in any of the seed objects (skipping
/// the rtld at slot 0). Returns `None` when no object exports the name.
fn find_extern_symbol(st: &RtldState, name: &[u8]) -> Option<usize> {
    for i in 1..st.count {
        let obj = &st.objects[i];
        if obj.gnu_hash.is_null() {
            continue;
        }
        if let Some(sym) = unsafe {
            crate::common::elf::symbol::gnu_hash_lookup(
                obj.gnu_hash,
                obj.symtab,
                obj.strtab,
                name,
                None,
            )
        } && sym.st_value != 0
        {
            return Some(obj.base + sym.st_value as usize);
        }
    }
    None
}

/// Re-export the dlfcn function table builder so other crates do not have to
/// reach into the elf submodule directly.
pub fn loader_dlfcn_table() -> RtldDlfcnV1 {
    dlfcn::build_table()
}
