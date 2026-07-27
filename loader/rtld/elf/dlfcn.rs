//! SPDX-License-Identifier: GPL-2.0-only
//! `RtldDlfcnV1` implementation — public dlfcn entry points.
//!
//! Every entry takes a caller-supplied `errbuf` (size `errbuf_len`) and
//! writes a NUL-terminated UTF-8 error string on failure. Mutating calls
//! (dlopen / dlclose) acquire `RtldState::dl_lock`.
//!
//! Handle conventions:
//! - `(void*)-1` (RTLD_NEXT) — passed to `dlsym` only.
//! - `null`     (RTLD_DEFAULT)         — global scope lookup, never a real
//!                                       LinkMap.
//! - `1`        (DEFAULT_HANDLE_MARKER) — return value of `dlopen(NULL, ...)`;
//!                                       behaves like RTLD_DEFAULT.
//! - any other value — pointer to a real `LinkMap` produced by `load_object`.

use crate::common::elf::dynamic;
use crate::common::elf::types::*;
use crate::common::link_map::{LinkMap, RtldState, link_flags};
use crate::rtld::elf::object::{
    self, RTLD_GLOBAL_FLAG, RTLD_NODELETE_FLAG, RTLD_NOLOAD_FLAG, RTLD_NOW_FLAG, arena_alloc,
    arena_intern, ensure_arena, load_object, run_fini, unmap_runtime_object,
};
use crate::rtld::elf::scope;
use crate::rtld::elf::tls;
use crate::rtld::state;
use trona_kernel::core_types::{DlInfo, DlIterateCallback, DlPhdrInfo, RtldDlfcnV1};

/// Handle returned by `dlopen(NULL, ...)`. Distinct from RTLD_DEFAULT (NULL)
/// so callers can tell that they obtained a handle, while behaviour
/// converges in `dlsym`.
const DEFAULT_HANDLE_MARKER: *mut u8 = 1 as *mut u8;
const RTLD_NEXT_HANDLE: *mut u8 = usize::MAX as *mut u8;

/// Construct the function table that the rtld publishes via
/// `trona_loader_runtime_install`.
pub const fn build_table() -> RtldDlfcnV1 {
    RtldDlfcnV1 {
        dlopen: dlopen_impl,
        dlsym_from: dlsym_from_impl,
        dlclose: dlclose_impl,
        dladdr: dladdr_impl,
        dl_iterate_phdr: dl_iterate_phdr_impl,
        tls_addr: tls::tls_addr_impl,
        tls_destroy: tls::tls_destroy_impl,
    }
}

// ---------------------------------------------------------------------------
// Public entries
// ---------------------------------------------------------------------------

unsafe extern "C" fn dlopen_impl(
    path: *const u8,
    flags: i32,
    errbuf: *mut u8,
    errbuf_len: usize,
) -> *mut u8 {
    if path.is_null() {
        return DEFAULT_HANDLE_MARKER;
    }
    let st = unsafe { state::get_state() };
    if let Err(e) = ensure_arena(st) {
        write_err(errbuf, errbuf_len, b"dlopen: arena init failed");
        let _ = e;
        return core::ptr::null_mut();
    }

    st.dl_lock.acquire();
    let result = unsafe { dlopen_locked(st, path, flags, errbuf, errbuf_len) };
    st.dl_lock.release();
    result
}

/// Maximum number of objects (root + transitive deps) that a single dlopen
/// invocation may load. Larger graphs return `dlopen: dependency graph too
/// deep` rather than corrupting the post-order tracker.
const MAX_DLOPEN_GRAPH: usize = 64;

/// Post-order list of LinkMap pointers newly loaded during a single
/// `dlopen()` call. Items appear in dependency-last order (a dependency is
/// appended before the object that referenced it). Items that were already
/// in the chain (reused) are NOT added because they are already relocated
/// and initialized.
struct LoadOrder {
    items: [*mut LinkMap; MAX_DLOPEN_GRAPH],
    count: usize,
}

impl LoadOrder {
    const fn empty() -> Self {
        LoadOrder {
            items: [core::ptr::null_mut(); MAX_DLOPEN_GRAPH],
            count: 0,
        }
    }
    fn push(&mut self, lm: *mut LinkMap) -> Result<(), ()> {
        if self.count >= MAX_DLOPEN_GRAPH {
            return Err(());
        }
        self.items[self.count] = lm;
        self.count += 1;
        Ok(())
    }
}

unsafe fn dlopen_locked(
    st: &mut RtldState,
    path: *const u8,
    flags: i32,
    errbuf: *mut u8,
    errbuf_len: usize,
) -> *mut u8 {
    let path_bytes = unsafe { cstr_slice(path) };

    // Already in the dlopen chain → bump refcount, refresh handle flags,
    // return the existing entry. No relocation/init re-run.
    if let Some(existing) = object::find_in_chain_by_name(st, path_bytes) {
        let lm = unsafe { &mut *existing };
        lm.refcount = lm.refcount.saturating_add(1);
        update_handle_flags(lm, flags);
        return existing as *mut u8;
    }
    // Already a startup-loaded object → return seed slot pointer with no
    // refcount mutation (STARTUP objects are pinned).
    if let Some(idx) = object::find_loaded_object(st, path_bytes) {
        return &mut st.objects[idx] as *mut LinkMap as *mut u8;
    }

    if flags & RTLD_NOLOAD_FLAG != 0 {
        write_err(errbuf, errbuf_len, b"dlopen: RTLD_NOLOAD: not loaded");
        return core::ptr::null_mut();
    }

    // Recursive load: each newly-loaded object (root + every transitive
    // dependency that wasn't already in the chain) joins `order` AFTER its
    // own dependencies, giving a topologically-sorted dependency-last list.
    let mut order = LoadOrder::empty();
    let lm_ptr =
        match unsafe { load_recursive(st, path, flags, true, &mut order, errbuf, errbuf_len) } {
            Ok(p) => p,
            Err(()) => {
                rollback(st, &order);
                return core::ptr::null_mut();
            }
        };

    // Relocate every freshly-loaded object in dependency-last order so that
    // every reference a parent might emit can already see its dependencies'
    // symbols. TLSDESC entries are pre-bound out-of-band so the generic
    // relocator sees them as already-resolved no-ops.
    for i in 0..order.count {
        let lm = order.items[i];
        if unsafe { tls::bind_tlsdesc(st, lm) }.is_err() {
            write_err(errbuf, errbuf_len, b"dlopen: tlsdesc bind failed");
            rollback(st, &order);
            return core::ptr::null_mut();
        }
        if let Err(_e) = unsafe { object::relocate_runtime_object(st, lm) } {
            write_err(errbuf, errbuf_len, b"dlopen: relocation failed");
            rollback(st, &order);
            return core::ptr::null_mut();
        }
        let lm_ref = unsafe { &mut *lm };
        if !lm_ref.pltgot.is_null() {
            unsafe { object::install_got_entries(lm_ref) };
        }
        // No protection fix-up: each run was mapped with its final protection
        // (text R-X, data R-W), so text is already executable and W^X holds.
    }

    // Run constructors in the same dependency-last order. `run_init` is
    // idempotent via the `INIT_DONE` flag.
    for i in 0..order.count {
        let lm = order.items[i];
        let lm_ref = unsafe { &mut *lm };
        if !lm_ref.has_flag(link_flags::INIT_DONE) {
            unsafe { object::run_init(lm_ref) };
        }
    }

    let _ = flags & RTLD_NOW_FLAG;
    lm_ptr as *mut u8
}

/// Recursively load `path` and every DT_NEEDED transitive dependency,
/// appending each newly-loaded object to `order` in dependency-last
/// (post-order) sequence. Direct dependencies are recorded on the LinkMap's
/// `deps_ptr` for later handle-scoped lookups.
///
/// `is_root` controls how the loaded object's scope flags are stamped:
/// the root inherits caller-supplied `flags`; recursive dependencies join
/// the global scope (mirroring how DT_NEEDED is handled at startup).
unsafe fn load_recursive(
    st: &mut RtldState,
    path: *const u8,
    flags: i32,
    is_root: bool,
    order: &mut LoadOrder,
    errbuf: *mut u8,
    errbuf_len: usize,
) -> Result<*mut LinkMap, ()> {
    let path_bytes = unsafe { cstr_slice(path) };

    // Already in chain → reuse. Only the root call observes refcount and
    // flag updates; dependency reuse is silent.
    if let Some(existing) = object::find_in_chain_by_name(st, path_bytes) {
        if is_root {
            let lm = unsafe { &mut *existing };
            lm.refcount = lm.refcount.saturating_add(1);
            update_handle_flags(lm, flags);
        }
        return Ok(existing);
    }
    // Already a seed object → reuse pointer; never join `order` because
    // STARTUP objects are already relocated and initialized.
    if let Some(idx) = object::find_loaded_object(st, path_bytes) {
        return Ok(&mut st.objects[idx] as *mut LinkMap);
    }

    let lm_ptr = match unsafe { load_object(st, path) } {
        Ok(p) => p,
        Err(e) => {
            write_err_load(errbuf, errbuf_len, e);
            return Err(());
        }
    };

    {
        let lm = unsafe { &mut *lm_ptr };
        if is_root {
            update_handle_flags(lm, flags);
        } else {
            lm.set_flag(link_flags::RTLD_GLOBAL);
        }
        if lm.tls_memsz > 0 {
            tls::register_runtime_module(st, lm);
        }
    }

    // Snapshot DT_NEEDED offsets and the strtab/runpath/rpath inputs we
    // need to recurse. The recursive load_object calls grow the arena, but
    // `lm.strtab` points into the new object's PT_LOAD mapping (not the
    // arena), so the snapshot stays valid across the descent.
    let (needed_offsets, needed_count, strtab, runpath, rpath) = {
        let lm = unsafe { &mut *lm_ptr };
        if lm.dynamic.is_null() || lm.strtab.is_null() {
            ([0u64; 32], 0usize, lm.strtab, lm.runpath, lm.rpath)
        } else {
            let mut buf: [u64; 32] = [0; 32];
            let mut n = 0usize;
            for off in unsafe { dynamic::NeededIter::new(lm.dynamic) } {
                if n >= buf.len() {
                    break;
                }
                buf[n] = off;
                n += 1;
            }
            (buf, n, lm.strtab, lm.runpath, lm.rpath)
        }
    };

    let mut deps_array: [*mut LinkMap; 32] = [core::ptr::null_mut(); 32];
    let mut dep_count = 0usize;

    for i in 0..needed_count {
        let off = needed_offsets[i];
        let name_ptr = unsafe { strtab.add(off as usize) };
        let name = unsafe { cstr_slice(name_ptr) };

        let resolved = match resolve_dependency_path(st, name, runpath, rpath) {
            Some(p) => p,
            None => {
                write_err(errbuf, errbuf_len, b"dlopen: dependency not found");
                return Err(());
            }
        };

        // Recurse — dependency-last ordering is preserved because the
        // recursive call appends dep to `order` before returning.
        let dep = unsafe { load_recursive(st, resolved, 0, false, order, errbuf, errbuf_len)? };
        if dep_count < deps_array.len() {
            deps_array[dep_count] = dep;
            dep_count += 1;
        }
    }

    // Persist the direct-dependency vector for handle-scoped lookups.
    if dep_count > 0 {
        let bytes = dep_count * core::mem::size_of::<*mut LinkMap>();
        let p = match arena_alloc(&mut st.arena, bytes, core::mem::align_of::<*mut LinkMap>()) {
            Some(p) => p as *mut *mut LinkMap,
            None => {
                write_err(errbuf, errbuf_len, b"dlopen: arena exhausted");
                return Err(());
            }
        };
        for i in 0..dep_count {
            unsafe { p.add(i).write(deps_array[i]) };
        }
        let lm_mut = unsafe { &mut *lm_ptr };
        lm_mut.deps_ptr = p;
        lm_mut.deps_count = dep_count as u32;
    }

    // Post-order: append AFTER all dependencies of this node are queued.
    if order.push(lm_ptr).is_err() {
        write_err(errbuf, errbuf_len, b"dlopen: dependency graph too deep");
        return Err(());
    }

    Ok(lm_ptr)
}

/// Undo a partially-completed dlopen by tearing down every object in
/// `order`. Walks in reverse so dependents go before dependencies. STARTUP
/// objects are skipped; reused chain objects never appear in `order`.
fn rollback(st: &mut RtldState, order: &LoadOrder) {
    for i in (0..order.count).rev() {
        let lm = order.items[i];
        if lm.is_null() {
            continue;
        }
        if unsafe { (*lm).has_flag(link_flags::STARTUP) } {
            continue;
        }
        unlink_and_unmap(st, lm);
    }
}

unsafe extern "C" fn dlsym_from_impl(
    handle: *mut u8,
    symbol: *const u8,
    caller_pc: usize,
    errbuf: *mut u8,
    errbuf_len: usize,
) -> *mut u8 {
    if symbol.is_null() {
        write_err(errbuf, errbuf_len, b"dlsym: null symbol name");
        return core::ptr::null_mut();
    }
    let name = unsafe { cstr_slice(symbol) };
    let st = unsafe { state::get_state_ref() };

    let resolved = if handle == RTLD_NEXT_HANDLE {
        scope::resolve_next_after(st, caller_pc, name)
    } else if handle.is_null() || handle == DEFAULT_HANDLE_MARKER {
        scope::resolve_default(st, name)
    } else {
        scope::resolve_in_handle(handle as *const LinkMap, name)
    };

    match resolved {
        Some(0) => {
            write_err(errbuf, errbuf_len, b"dlsym: undefined symbol");
            core::ptr::null_mut()
        }
        Some(addr) => addr as *mut u8,
        None => {
            write_err(errbuf, errbuf_len, b"dlsym: symbol not found");
            core::ptr::null_mut()
        }
    }
}

unsafe extern "C" fn dlclose_impl(handle: *mut u8, errbuf: *mut u8, errbuf_len: usize) -> i32 {
    if handle.is_null() || handle == DEFAULT_HANDLE_MARKER || handle == RTLD_NEXT_HANDLE {
        return 0;
    }
    let st = unsafe { state::get_state() };
    st.dl_lock.acquire();
    let lm_ptr = handle as *mut LinkMap;
    let lm = unsafe { &mut *lm_ptr };

    // Startup objects are pinned forever.
    if lm.has_flag(link_flags::STARTUP) {
        st.dl_lock.release();
        return 0;
    }

    if lm.refcount > 1 {
        lm.refcount -= 1;
        st.dl_lock.release();
        return 0;
    }
    lm.refcount = 0;

    if lm.has_flag(link_flags::RTLD_NODELETE) {
        // Keep the mapping but stop counting references. Subsequent dlopens
        // will reuse the existing entry.
        st.dl_lock.release();
        return 0;
    }

    unsafe { run_fini(lm) };
    unlink_and_unmap(st, lm_ptr);
    st.dl_lock.release();
    let _ = (errbuf, errbuf_len);
    0
}

unsafe extern "C" fn dladdr_impl(
    addr: *const u8,
    info: *mut DlInfo,
    errbuf: *mut u8,
    errbuf_len: usize,
) -> i32 {
    if info.is_null() {
        write_err(errbuf, errbuf_len, b"dladdr: null info pointer");
        return 0;
    }
    let st = unsafe { state::get_state_ref() };
    let pc = addr as usize;
    let lm_ptr = match scope::locate_object_by_pc(st, pc) {
        Some(p) => p,
        None => return 0,
    };
    let lm = unsafe { &*lm_ptr };
    let mut out = DlInfo::zeroed();
    out.dli_fname = if !lm.path.is_null() { lm.path } else { lm.name };
    out.dli_fbase = lm.base as *mut u8;
    if let Some((sname_ptr, saddr)) = nearest_symbol(lm, pc) {
        out.dli_sname = sname_ptr;
        out.dli_saddr = saddr as *mut u8;
    }
    unsafe { core::ptr::write(info, out) };
    1
}

unsafe extern "C" fn dl_iterate_phdr_impl(
    callback: DlIterateCallback,
    data: *mut u8,
    _errbuf: *mut u8,
    _errbuf_len: usize,
) -> i32 {
    let st = unsafe { state::get_state_ref() };
    let size = core::mem::size_of::<DlPhdrInfo>();

    // Seed array first.
    for i in 0..st.count {
        if let Some(mut info) = build_phdr_info(&st.objects[i])
            && let r = unsafe { callback(&mut info, size, data) }
            && r != 0
        {
            return r;
        }
    }
    // Then runtime chain.
    let mut cur = st.dl_head;
    while !cur.is_null() {
        let lm = unsafe { &*cur };
        if let Some(mut info) = build_phdr_info(lm)
            && let r = unsafe { callback(&mut info, size, data) }
            && r != 0
        {
            return r;
        }
        cur = lm.l_next;
    }
    0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_phdr_info(lm: &LinkMap) -> Option<DlPhdrInfo> {
    if lm.phdr.is_null() || lm.phnum == 0 {
        return None;
    }
    Some(DlPhdrInfo {
        dlpi_addr: lm.base as u64,
        dlpi_name: if !lm.name.is_null() {
            lm.name
        } else {
            b"\0".as_ptr()
        },
        dlpi_phdr: lm.phdr as *const u8,
        dlpi_phnum: lm.phnum,
        _pad0: 0,
        _pad1: 0,
    })
}

fn nearest_symbol(lm: &LinkMap, pc: usize) -> Option<(*const u8, u64)> {
    if lm.symtab.is_null() || lm.strtab.is_null() {
        return None;
    }
    let count = object::sym_count(lm);
    if count == 0 {
        return None;
    }
    let mut best: Option<(u64, u32)> = None;
    let bias = lm.base as u64;
    for i in 0..count {
        let sym = unsafe { &*lm.symtab.add(i) };
        if sym.st_shndx == SHN_UNDEF || sym.st_value == 0 {
            continue;
        }
        let addr = bias + sym.st_value;
        if addr <= pc as u64 && best.map(|(a, _)| addr > a).unwrap_or(true) {
            best = Some((addr, sym.st_name));
        }
    }
    best.map(|(addr, name)| {
        let name_ptr = unsafe { lm.strtab.add(name as usize) };
        (name_ptr, addr)
    })
}

fn update_handle_flags(lm: &mut LinkMap, flags: i32) {
    if flags & RTLD_GLOBAL_FLAG != 0 {
        lm.set_flag(link_flags::RTLD_GLOBAL);
        lm.clear_flag(link_flags::RTLD_LOCAL);
    } else {
        lm.set_flag(link_flags::RTLD_LOCAL);
    }
    if flags & RTLD_NODELETE_FLAG != 0 {
        lm.set_flag(link_flags::RTLD_NODELETE);
    }
}

fn resolve_dependency_path(
    st: &mut RtldState,
    name: &[u8],
    runpath: *const u8,
    rpath: *const u8,
) -> Option<*const u8> {
    // Slash → take verbatim.
    if name.iter().any(|b| *b == b'/') {
        let interned = arena_intern(&mut st.arena, name)?;
        return Some(interned);
    }
    // RUNPATH first, then RPATH, then default lib search.
    if !runpath.is_null() {
        let runpath_bytes = unsafe { cstr_slice(runpath) };
        if let Some(p) = object::search_paths(&mut st.arena, runpath_bytes, name) {
            return Some(p);
        }
    }
    if !rpath.is_null() {
        let rpath_bytes = unsafe { cstr_slice(rpath) };
        if let Some(p) = object::search_paths(&mut st.arena, rpath_bytes, name) {
            return Some(p);
        }
    }
    // Default: /usr/lib then /lib.
    object::search_paths(&mut st.arena, b"/usr/lib:/lib", name)
}

fn unlink_and_unmap(st: &mut RtldState, lm_ptr: *mut LinkMap) {
    let lm = unsafe { &mut *lm_ptr };
    if !lm.l_prev.is_null() {
        unsafe { (*lm.l_prev).l_next = lm.l_next };
    } else if st.dl_head == lm_ptr {
        st.dl_head = lm.l_next;
    }
    if !lm.l_next.is_null() {
        unsafe { (*lm.l_next).l_prev = lm.l_prev };
    }
    lm.l_prev = core::ptr::null_mut();
    lm.l_next = core::ptr::null_mut();
    unsafe { unmap_runtime_object(lm) };
}

unsafe fn cstr_slice(p: *const u8) -> &'static [u8] {
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    unsafe { core::slice::from_raw_parts(p, len) }
}

fn write_err(buf: *mut u8, len: usize, msg: &[u8]) {
    if buf.is_null() || len == 0 {
        return;
    }
    let copy = msg.len().min(len.saturating_sub(1));
    unsafe {
        core::ptr::copy_nonoverlapping(msg.as_ptr(), buf, copy);
        *buf.add(copy) = 0;
    }
}

fn write_err_load(buf: *mut u8, len: usize, err: object::LoadError) {
    let s: &[u8] = match err {
        object::LoadError::ArenaMmapFailed => b"dlopen: arena mmap failed",
        object::LoadError::OpenFailed => b"dlopen: open failed",
        object::LoadError::StatFailed => b"dlopen: stat failed",
        object::LoadError::ReadFailed => b"dlopen: read failed",
        object::LoadError::NotElf => b"dlopen: not a valid ELF",
        object::LoadError::UnsupportedClass => b"dlopen: unsupported ELF class",
        object::LoadError::UnsupportedMachine => b"dlopen: unsupported machine",
        object::LoadError::NoLoadable => b"dlopen: no PT_LOAD segments",
        object::LoadError::DsoWindowExhausted => b"dlopen: DSO window exhausted",
        object::LoadError::RunPlanFailed => b"dlopen: image run plan failed",
        object::LoadError::ImageReserveFailed => b"dlopen: image reservation failed",
        object::LoadError::ImageAliasFailed => b"dlopen: image alias failed",
        object::LoadError::ImageMapRunFailed => b"dlopen: image run mapping failed",
        object::LoadError::MmapFailed => b"dlopen: mmap failed",
        object::LoadError::Mprotect => b"dlopen: mprotect failed",
        object::LoadError::OutOfArena => b"dlopen: rtld arena exhausted",
        object::LoadError::DependencyMissing => b"dlopen: dependency missing",
        object::LoadError::RelocationFailed => b"dlopen: relocation failed",
    };
    write_err(buf, len, s);
}
