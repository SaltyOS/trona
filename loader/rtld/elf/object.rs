//! SPDX-License-Identifier: GPL-2.0-only
//! Per-object helpers shared by startup and runtime paths.
//!
//! Owns:
//! - `apply_dyn_info` — turn `DynInfo` RVAs into absolute pointers.
//! - `relocate_object` — apply both RELA and JMPREL tables.
//! - `install_got_entries` — wire GOT[1]/GOT[2] for lazy PLT.
//! - `_dl_fixup` — lazy PLT resolver, called from arch trampoline.
//! - `find_loaded_object` / `find_in_chain_by_name` — name-based LinkMap
//!   lookup.
//! - `find_main_ehdr_from_at_phdr` — backwards search for the main ELF
//!   header from `AT_PHDR`.
//! - `load_object` — runtime dlopen DSO loader (mmap, parse, link,
//!   relocate). Allocates LinkMaps from `RtldState::arena`.

use crate::common::elf::dynamic;
use crate::common::elf::header;
use crate::common::elf::reloc;
use crate::common::elf::run_plan;
use crate::common::elf::types::*;
use crate::common::image::{Run, RunPlan};
use crate::common::link_map::{ArenaState, LinkMap, RtldState, link_flags};
use crate::rtld::elf::scope;
use crate::rtld::serial;
use crate::rtld::state;

/// Resolve the RVAs in `lm.dyn_info` into absolute pointers stored on `lm`.
///
/// # Safety
/// `lm.base` and `lm.dyn_info` must be valid; `lm.dynamic` must point at the
/// already-mapped PT_DYNAMIC region.
pub unsafe fn apply_dyn_info(lm: &mut LinkMap) {
    let base = lm.base;
    let di = lm.dyn_info;

    lm.symtab = (base + di.symtab as usize) as *const Elf64Sym;
    lm.strtab = (base + di.strtab as usize) as *const u8;
    lm.strsz = di.strsz as usize;

    if di.gnu_hash != 0 {
        lm.gnu_hash = (base + di.gnu_hash as usize) as *const u32;
    }
    if di.rela != 0 {
        lm.rela = (base + di.rela as usize) as *const Elf64Rela;
        let ent = if di.relaent != 0 {
            di.relaent as usize
        } else {
            core::mem::size_of::<Elf64Rela>()
        };
        lm.rela_count = di.relasz as usize / ent;
    }
    if di.jmprel != 0 {
        lm.jmprel = (base + di.jmprel as usize) as *const Elf64Rela;
        lm.jmprel_count = di.pltrelsz as usize / core::mem::size_of::<Elf64Rela>();
    }
    if di.pltgot != 0 {
        lm.pltgot = (base + di.pltgot as usize) as *mut usize;
    }
    if di.init != 0 {
        lm.init = base + di.init as usize;
    }
    if di.fini != 0 {
        lm.fini = base + di.fini as usize;
    }
    if di.init_array != 0 {
        lm.init_array = base + di.init_array as usize;
        lm.init_arraysz = di.init_arraysz as usize;
    }
    if di.fini_array != 0 {
        lm.fini_array = base + di.fini_array as usize;
        lm.fini_arraysz = di.fini_arraysz as usize;
    }
    if di.verdef != 0 {
        lm.verdef = (base + di.verdef as usize) as *const u8;
        lm.verdef_num = di.verdef_num as u32;
    }
    if di.verneed != 0 {
        lm.verneed = (base + di.verneed as usize) as *const u8;
        lm.verneed_num = di.verneed_num as u32;
    }
    if di.versym != 0 {
        lm.versym = (base + di.versym as usize) as *const u16;
    }
    if di.runpath != 0 && !lm.strtab.is_null() {
        lm.runpath = unsafe { lm.strtab.add(di.runpath as usize) };
    }
    if di.rpath != 0 && !lm.strtab.is_null() {
        lm.rpath = unsafe { lm.strtab.add(di.rpath as usize) };
    }

    // Cache the symbol-table entry count so lookup / dladdr paths can read
    // it in O(1). Without this every call would walk the GNU hash chains or
    // fall back to the strtab-symtab byte-gap estimate.
    lm.nsyms = compute_nsyms(lm) as u32;
}

/// Compute the precise symbol-table entry count from whichever hash table
/// the object provides. Called exactly once per LinkMap by `apply_dyn_info`;
/// the result is cached in `LinkMap::nsyms`.
fn compute_nsyms(lm: &LinkMap) -> usize {
    if lm.symtab.is_null() {
        return 0;
    }
    if lm.dyn_info.hash != 0 {
        let hash_ptr = (lm.base + lm.dyn_info.hash as usize) as *const u32;
        return unsafe { *hash_ptr.add(1) as usize };
    }
    if !lm.gnu_hash.is_null() {
        return gnu_hash_max_index(lm.gnu_hash);
    }
    if lm.strtab.is_null() {
        return 0;
    }
    let gap = (lm.strtab as usize).saturating_sub(lm.symtab as usize);
    gap / core::mem::size_of::<Elf64Sym>()
}

/// Apply both RELA and JMPREL relocation tables on the object at `idx` using
/// global-scope symbol resolution. Sets the `RELOCATED` flag on success.
///
/// # Safety
/// All objects in `st` must have valid symtab/strtab and the target object
/// must be mapped writable for the duration of the call.
pub unsafe fn relocate_object(st: &mut RtldState, idx: usize) {
    let base = st.objects[idx].base;

    let rela_ptr = st.objects[idx].rela;
    let rela_count = st.objects[idx].rela_count;
    if !rela_ptr.is_null() && rela_count > 0 {
        if let Err(err) = unsafe {
            reloc::apply_rela_table(base, rela_ptr, rela_count, |sym_idx| {
                scope::resolve_symbol_global(st, idx, sym_idx)
            })
        } {
            report_relocation_error(err);
        }
    }

    let jmprel_ptr = st.objects[idx].jmprel;
    let jmprel_count = st.objects[idx].jmprel_count;
    if !jmprel_ptr.is_null() && jmprel_count > 0 {
        if let Err(err) = unsafe {
            reloc::apply_rela_table(base, jmprel_ptr, jmprel_count, |sym_idx| {
                scope::resolve_symbol_global(st, idx, sym_idx)
            })
        } {
            report_relocation_error(err);
        }
    }

    st.objects[idx].set_flag(link_flags::RELOCATED);
}

/// Apply both RELA and JMPREL on a heap-resident `LinkMap` (runtime dlopen).
/// Symbol resolution walks the dlopen chain so the new object can see all
/// previously-loaded scopes.
///
/// # Safety
/// `lm` must be a fully-mapped, writable runtime object whose symtab / strtab
/// have been resolved by [`apply_dyn_info`].
pub unsafe fn relocate_runtime_object(
    st: &RtldState,
    lm: *mut LinkMap,
) -> Result<(), reloc::RelocError> {
    let lm_ref = unsafe { &mut *lm };
    let base = lm_ref.base;

    let rela_ptr = lm_ref.rela;
    let rela_count = lm_ref.rela_count;
    if !rela_ptr.is_null() && rela_count > 0 {
        unsafe {
            reloc::apply_rela_table(base, rela_ptr, rela_count, |sym_idx| {
                scope::resolve_symbol_for_runtime(st, lm, sym_idx)
            })?;
        }
    }

    let jmprel_ptr = lm_ref.jmprel;
    let jmprel_count = lm_ref.jmprel_count;
    if !jmprel_ptr.is_null() && jmprel_count > 0 {
        unsafe {
            reloc::apply_rela_table(base, jmprel_ptr, jmprel_count, |sym_idx| {
                scope::resolve_symbol_for_runtime(st, lm, sym_idx)
            })?;
        }
    }

    lm_ref.set_flag(link_flags::RELOCATED);
    Ok(())
}

/// Install GOT[1] (link_map*) and GOT[2] (_dl_runtime_resolve) for lazy PLT.
///
/// # Safety
/// `lm.pltgot` must point to a valid, writable GOT.
pub unsafe fn install_got_entries(lm: &mut LinkMap) {
    if lm.pltgot.is_null() {
        return;
    }
    unsafe extern "C" {
        fn _dl_runtime_resolve();
    }
    unsafe { *lm.pltgot.add(1) = lm as *const LinkMap as usize };
    unsafe { *lm.pltgot.add(2) = _dl_runtime_resolve as *const () as usize };
}

/// Lazy PLT resolver — called from `_dl_runtime_resolve` arch trampoline.
///
/// # Safety
/// Called with the link_map pointer and relocation index from the PLT stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _dl_fixup(link_map: *mut LinkMap, rel_idx: usize) -> usize {
    let lm = unsafe { &*link_map };
    let rela = unsafe { &*lm.jmprel.add(rel_idx) };
    let sym_idx = elf64_r_sym(rela.r_info);

    let st = unsafe { state::get_state_ref() };

    // First try to locate the caller in the boot-time array (fast path for
    // startup objects); fall back to chain walk for runtime-loaded objects.
    let symval = if let Some(idx) = chain_index_in_seed(st, link_map) {
        scope::resolve_symbol_global(st, idx, sym_idx).unwrap_or(0)
    } else {
        scope::resolve_symbol_for_runtime(st, link_map, sym_idx).unwrap_or(0)
    };

    let target = (lm.base as u64 + rela.r_offset) as *mut u64;
    unsafe { target.write(symval) };
    symval as usize
}

fn chain_index_in_seed(st: &RtldState, lm: *const LinkMap) -> Option<usize> {
    for i in 0..st.count {
        if core::ptr::eq(&st.objects[i] as *const _, lm) {
            return Some(i);
        }
    }
    None
}

/// Locate a startup-object slot by NUL-terminated name.
pub fn find_loaded_object(st: &RtldState, name: &[u8]) -> Option<usize> {
    for i in 0..st.count {
        // `name` is a DT_NEEDED string — a soname/basename, never a full path.
        // A VFS-loaded object stores its resolved path in `name`, so its
        // DT_SONAME is the field that matches DT_NEEDED; check it first, then
        // fall back to `name` (a basename for pre-mapped objects). Matching only
        // `name` reloads the same library once per DT_NEEDED reference.
        let obj = &st.objects[i];
        if !obj.soname.is_null() && name_eq(obj.soname, name) {
            return Some(i);
        }
        if !obj.name.is_null() && name_eq(obj.name, name) {
            return Some(i);
        }
    }
    None
}

/// Walk the dlopen chain looking for an object whose `path`, `name`, or
/// `soname` matches `needle`.
pub fn find_in_chain_by_name(st: &RtldState, needle: &[u8]) -> Option<*mut LinkMap> {
    let mut cur = st.dl_head;
    while !cur.is_null() {
        let lm = unsafe { &*cur };
        if !lm.path.is_null() && name_eq(lm.path, needle) {
            return Some(cur);
        }
        if !lm.soname.is_null() && name_eq(lm.soname, needle) {
            return Some(cur);
        }
        if !lm.name.is_null() && name_eq(lm.name, needle) {
            return Some(cur);
        }
        cur = lm.l_next;
    }
    None
}

fn name_eq(c_str: *const u8, needle: &[u8]) -> bool {
    let mut i = 0;
    while i < needle.len() {
        if unsafe { *c_str.add(i) } != needle[i] {
            return false;
        }
        i += 1;
    }
    unsafe { *c_str.add(i) == 0 }
}

/// Return the precise number of symbols in `lm.symtab`. Reads the cached
/// `LinkMap::nsyms` value populated once by [`apply_dyn_info`]; falls back
/// to recomputing on the fly if the cache happens to be zero (e.g. the
/// LinkMap was constructed without going through `apply_dyn_info`).
pub fn sym_count(lm: &LinkMap) -> usize {
    if lm.nsyms != 0 {
        return lm.nsyms as usize;
    }
    compute_nsyms(lm)
}

/// Walk the GNU hash table to find the largest symbol index it references,
/// then add one for an inclusive count. Used as a fallback when DT_HASH is
/// absent (DT_GNU_HASH does not expose `nchain` directly).
fn gnu_hash_max_index(gnu_hash: *const u32) -> usize {
    let nbuckets = unsafe { *gnu_hash } as usize;
    let symoffset = unsafe { *gnu_hash.add(1) } as usize;
    let bloom_size = unsafe { *gnu_hash.add(2) } as usize;
    if nbuckets == 0 {
        return symoffset;
    }
    // Header is 4 u32s; bloom occupies `bloom_size` u64s == 2*bloom_size u32s.
    let buckets = unsafe { gnu_hash.add(4 + 2 * bloom_size) };
    let chains = unsafe { buckets.add(nbuckets) };

    let mut max_idx = symoffset;
    for b in 0..nbuckets {
        let mut idx = unsafe { *buckets.add(b) } as usize;
        if idx < symoffset {
            continue;
        }
        loop {
            if idx > max_idx {
                max_idx = idx;
            }
            let chain_val = unsafe { *chains.add(idx - symoffset) };
            if chain_val & 1 != 0 {
                break;
            }
            idx += 1;
        }
    }
    max_idx + 1
}

/// Reverse-scan from `at_phdr` for an `Elf64Ehdr` whose program-header
/// metadata matches `at_phent`/`at_phnum` and whose `e_phoff` lands exactly
/// on `at_phdr`.
///
/// # Safety
/// The page below `at_phdr` must be readable.
pub unsafe fn find_main_ehdr_from_at_phdr(
    at_phdr: usize,
    at_phent: usize,
    at_phnum: usize,
) -> Option<&'static Elf64Ehdr> {
    let mut back = 0usize;
    while back <= PAGE_SIZE {
        let cand_addr = at_phdr.checked_sub(back)?;
        let cand = unsafe { &*(cand_addr as *const Elf64Ehdr) };
        if cand.e_ident[0] == 0x7f
            && cand.e_ident[1] == b'E'
            && cand.e_ident[2] == b'L'
            && cand.e_ident[3] == b'F'
            && cand.e_phentsize as usize == at_phent
            && cand.e_phnum as usize == at_phnum
            && cand_addr.saturating_add(cand.e_phoff as usize) == at_phdr
        {
            return Some(cand);
        }
        back += 8;
    }
    None
}

fn report_relocation_error(err: reloc::RelocError) -> ! {
    match err {
        reloc::RelocError::UnsupportedType(typ) => {
            serial::print("[ldtrona-elf] unsupported relocation ");
            serial::print_hex(typ as u64);
            serial::putchar(b'\n');
        }
        reloc::RelocError::SymbolNotFound => {
            serial::print("[ldtrona-elf] relocation symbol not found\n");
        }
        reloc::RelocError::IfuncFailed => {
            serial::print("[ldtrona-elf] ifunc resolver failed\n");
        }
    }
    serial::fatal("relocation failed");
}

// ---------------------------------------------------------------------------
// Runtime DSO loader (dlopen path)
// ---------------------------------------------------------------------------

/// Errors from the runtime DSO loader.
#[derive(Clone, Copy, Debug)]
pub enum LoadError {
    ArenaMmapFailed,
    OpenFailed,
    StatFailed,
    ReadFailed,
    NotElf,
    UnsupportedClass,
    UnsupportedMachine,
    NoLoadable,
    DsoWindowExhausted,
    RunPlanFailed,
    ImageReserveFailed,
    ImageAliasFailed,
    ImageMapRunFailed,
    MmapFailed,
    Mprotect,
    OutOfArena,
    DependencyMissing,
    RelocationFailed,
}

const ARENA_DEFAULT_SIZE: usize = 4 * 1024 * 1024; // 4 MiB initial arena
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_ANONYMOUS_FLAG: i32 = 0x20;
const MAP_PRIVATE_FLAG: i32 = 0x02;
const MAP_FAILED_VAL: usize = usize::MAX;

/// Lazily initialize the rtld arena. Idempotent — first caller wins, others
/// observe the initialized state.
pub fn ensure_arena(st: &mut RtldState) -> Result<(), LoadError> {
    if st.arena.base != 0 {
        return Ok(());
    }
    st.arena.lock.acquire();
    if st.arena.base != 0 {
        st.arena.lock.release();
        return Ok(());
    }
    let mapped = unsafe {
        trona_runtime::client::mm::mmap_anonymous(
            core::ptr::null_mut(),
            ARENA_DEFAULT_SIZE as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS_FLAG | MAP_PRIVATE_FLAG,
        )
        .unwrap_or(MAP_FAILED_VAL as *mut u8)
    };
    if mapped as usize == MAP_FAILED_VAL || mapped.is_null() {
        st.arena.lock.release();
        return Err(LoadError::ArenaMmapFailed);
    }
    st.arena.base = mapped as usize;
    st.arena.size = ARENA_DEFAULT_SIZE;
    st.arena.cursor = 0;
    st.arena.lock.release();
    Ok(())
}

/// Bump-allocate `size` bytes from the arena with the requested alignment.
/// Returns a writable pointer into the arena or `None` when exhausted.
pub fn arena_alloc(arena: &mut ArenaState, size: usize, align: usize) -> Option<*mut u8> {
    arena.lock.acquire();
    let aligned_cursor = (arena.cursor + align - 1) & !(align - 1);
    if aligned_cursor.checked_add(size)? > arena.size {
        arena.lock.release();
        return None;
    }
    let p = (arena.base + aligned_cursor) as *mut u8;
    arena.cursor = aligned_cursor + size;
    arena.lock.release();
    Some(p)
}

/// Allocate a zeroed `LinkMap` from the arena.
pub fn arena_alloc_link_map(arena: &mut ArenaState) -> Option<*mut LinkMap> {
    let p = arena_alloc(
        arena,
        core::mem::size_of::<LinkMap>(),
        core::mem::align_of::<LinkMap>(),
    )? as *mut LinkMap;
    unsafe { core::ptr::write(p, LinkMap::zeroed()) };
    Some(p)
}

/// Intern a NUL-terminated string into the arena. Returns the new pointer or
/// `None` when the arena is exhausted.
pub fn arena_intern(arena: &mut ArenaState, src: &[u8]) -> Option<*const u8> {
    let total = src.len() + 1;
    let p = arena_alloc(arena, total, 1)?;
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), p, src.len());
        *p.add(src.len()) = 0;
    }
    Some(p as *const u8)
}

/// dlopen flags interpreted by the loader. Mirror the public `RTLD_*` macros
/// in `lib/basalt/c/include/dlfcn.h`. Kept here because the rtld must read
/// them without pulling libc into its dependency tree.
pub const RTLD_LAZY_FLAG: i32 = 0x0001;
pub const RTLD_NOW_FLAG: i32 = 0x0002;
pub const RTLD_NOLOAD_FLAG: i32 = 0x0004;
pub const RTLD_GLOBAL_FLAG: i32 = 0x0100;
pub const RTLD_NODELETE_FLAG: i32 = 0x1000;

/// Search `paths` (NUL-separated, LD_LIBRARY_PATH-style) for a file matching
/// `basename`. Returns the first hit interned into the arena, or `None` when
/// no path resolves.
pub fn search_paths(arena: &mut ArenaState, paths: &[u8], basename: &[u8]) -> Option<*const u8> {
    let mut start = 0usize;
    while start < paths.len() {
        let mut end = start;
        while end < paths.len() && paths[end] != b':' && paths[end] != 0 {
            end += 1;
        }
        if end > start {
            let dir = &paths[start..end];
            if let Some(joined) = path_join_intern(arena, dir, basename)
                && file_exists(joined)
            {
                return Some(joined);
            }
        }
        start = end + 1;
    }
    None
}

fn path_join_intern(arena: &mut ArenaState, dir: &[u8], base: &[u8]) -> Option<*const u8> {
    let need_sep = dir.last().copied() != Some(b'/');
    let total = dir.len() + (if need_sep { 1 } else { 0 }) + base.len() + 1;
    let p = arena_alloc(arena, total, 1)?;
    let mut off = 0usize;
    unsafe {
        core::ptr::copy_nonoverlapping(dir.as_ptr(), p, dir.len());
        off += dir.len();
        if need_sep {
            *p.add(off) = b'/';
            off += 1;
        }
        core::ptr::copy_nonoverlapping(base.as_ptr(), p.add(off), base.len());
        off += base.len();
        *p.add(off) = 0;
    }
    Some(p as *const u8)
}

fn file_exists(path: *const u8) -> bool {
    let fd = unsafe { trona_runtime::client::vfs::open_readonly(path).unwrap_or(-1) };
    if fd < 0 {
        return false;
    }
    let _ = unsafe { trona_runtime::client::vfs::close(fd) };
    true
}

/// Largest run buffer for one ELF run plan. A well-formed PIE has a handful of
/// PT_LOAD segments; the planner splits each BSS-only tail beyond
/// `p_filesz` into its own `ZeroFill` run, so the worst case is roughly two
/// runs per PT_LOAD (private file extent + trailing BSS), plus text and
/// rodata runs. 128 comfortably covers every plausible layout.
const MAX_RTLD_RUNS: usize = 128;

/// Scratch buffer for the ELF header + program headers read out of the code
/// MemoryObject before planning. Program headers always sit early in the file;
/// 8 KiB covers the ehdr plus a very large phdr table.
const RTLD_HEADER_SCRATCH: usize = 8192;

/// Return the basename (last `/`-separated component) of `name`. `ldsrv` owns
/// the library namespace, so resolution is by soname; a path-form input
/// resolves to its library identity.
fn basename(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b'/') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// Read the leading `out.len()`-bounded bytes of a code MemoryObject (its ELF
/// header + program headers) into `out` via `MO_READ`, returning the byte count
/// read. `MO_READ` pages a file-backed MO in through its pager transparently and
/// copies into this thread's IPC buffer; the caller holds no live IPC, so the
/// bytes are copied straight out to `out`.
fn read_headers(code_mo: trona_kernel::core_types::CapRef, mo_size: u64, out: &mut [u8]) -> usize {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() {
        return 0;
    }
    let buf = unsafe { (*ctx).ipc_buffer as *const u8 };
    if buf.is_null() {
        return 0;
    }
    let want_total = (mo_size as usize).min(out.len());
    let mut off = 0usize;
    while off < want_total {
        let want = (want_total - off).min(2048) as u64;
        let (err, got) = trona_kernel::invoke::mo_read(code_mo, off as u64, want);
        if err != 0 || got == 0 {
            break;
        }
        let got = (got as usize).min(want as usize);
        unsafe { core::ptr::copy_nonoverlapping(buf, out.as_mut_ptr().add(off), got) };
        off += got;
    }
    off
}

/// Load a DSO by `name` (a soname, or a path whose basename is the soname)
/// into the process address space and return a populated `LinkMap` *by value* —
/// without setting flags / refcount or linking it into any object store. Each
/// caller records the result in its own store (the startup `st.objects` array,
/// or the dlopen `st.dl_head` chain) and sets its own flags.
///
/// `ldsrv` resolves the name to a `READ|EXECUTE` code MemoryObject; the linker
/// reduces it to a run plan and maps each run — text `R-X`, rodata `R--`,
/// writable data a private copy-on-write child `R-W`, `.bss` zero-fill — into
/// one mmsrv image reservation (recorded as `LinkMap::image_id` for `dlclose`).
/// No segment is ever mapped writable-then-executable: every run carries its
/// final protection from the start.
///
/// DT_NEEDED resolution and relocation are run by the caller after every
/// dependency has its own `LinkMap`; relocations land on the writable data run,
/// and PT_GNU_RELRO is narrowed afterward by the caller.
///
/// # Safety
/// Callers must hold `st.dl_lock` during the chain mutation segment; `name`
/// must be a NUL-terminated byte string.
pub(crate) unsafe fn load_object_into(
    st: &mut RtldState,
    name: *const u8,
) -> Result<LinkMap, LoadError> {
    ensure_arena(st)?;

    let name_len = cstr_len(name);
    let name_bytes = unsafe { core::slice::from_raw_parts(name, name_len) };
    let interned = arena_intern(&mut st.arena, name_bytes).ok_or(LoadError::OutOfArena)?;

    // 1. Resolve the name to an execute-bearing code MemoryObject through ldsrv,
    //    which owns the library namespace.
    // SAFETY: rtld resolves only a loader-owned NUL-terminated DT_NEEDED name
    // after role caps have been initialized from its startup block.
    let resolved =
        match unsafe { trona_runtime::client::ldsrv::resolve_library(basename(name_bytes)) } {
            Ok(r) => r,
            Err(_) => return Err(LoadError::OpenFailed),
        };
    let code_mo = resolved.code_mo;
    let code_ref = trona_runtime::core::slot_alloc::resolved_cap_ref(code_mo.as_raw());

    // 2. Read the ELF header + program headers out of the code MO.
    let mut hdr = [0u8; RTLD_HEADER_SCRATCH];
    let hdr_len = read_headers(code_ref, resolved.mo_size, &mut hdr);
    let ehdr = match unsafe { header::validate_ehdr(hdr.as_ptr(), hdr_len) } {
        Ok(e) => e,
        Err(_) => return Err(LoadError::NotElf),
    };
    let phdrs = match unsafe { header::phdr_slice(hdr.as_ptr(), hdr_len, ehdr) } {
        Ok(p) => p,
        Err(_) => return Err(LoadError::NotElf),
    };

    // 3. Choose a load base inside the DSO window.
    let (span_lo, span_hi) = match header::load_span(phdrs) {
        Some(s) => s,
        None => return Err(LoadError::NoLoadable),
    };
    let span_size = page_align_up(span_hi as usize) - page_align_down(span_lo as usize);
    let load_base = chain_next_load_hint(st, span_size);
    if load_base == 0 {
        return Err(LoadError::DsoWindowExhausted);
    }

    // 4. Build the run plan and realize it into the DSO window through the
    //    self-mapping placement sink.
    let mut runs = [Run::EMPTY; MAX_RTLD_RUNS];
    let (envelope, run_count) =
        match run_plan::plan_elf(phdrs, load_base as u64, ehdr.e_entry, &mut runs) {
            Ok(r) => r,
            Err(_) => return Err(LoadError::RunPlanFailed),
        };
    let plan = RunPlan {
        envelope,
        runs: &runs[..run_count],
        carves: &[],
    };
    let image_id = match unsafe { crate::rtld::image_sink::place_image(code_ref, &plan) } {
        Ok(id) => id,
        Err(crate::rtld::image_sink::SinkError::Reserve) => {
            return Err(LoadError::ImageReserveFailed);
        }
        Err(crate::rtld::image_sink::SinkError::Alias) => {
            return Err(LoadError::ImageAliasFailed);
        }
        Err(crate::rtld::image_sink::SinkError::MapRun) => {
            return Err(LoadError::ImageMapRunFailed);
        }
    };
    // The per-run aliases now back the mapped regions in mmsrv; the linker's own
    // code MO copy is no longer needed.
    drop(code_mo);

    let envelope_end = envelope.base as usize + envelope.bytes as usize;

    // 5. Populate a LinkMap by value (the caller records it). Dynamic / TLS
    //    metadata is read from the now-mapped image.
    let mut lm_val = LinkMap::zeroed();
    let lm = &mut lm_val;
    lm.base = load_base as usize;
    lm.path = interned;
    lm.name = interned;
    lm.map_start = envelope.base as usize;
    lm.map_end = envelope_end;
    lm.map_prot = 0;
    lm.image_id = image_id;
    lm.e_type = ehdr.e_type;
    lm.entry = envelope.entry_pc as usize;
    lm.phdr = (load_base as usize + ehdr.e_phoff as usize) as *const Elf64Phdr;
    lm.phnum = ehdr.e_phnum;

    if let Some(dyn_ph) = header::find_dynamic_phdr(phdrs) {
        let dyn_ptr = (load_base as usize + dyn_ph.p_vaddr as usize) as *const Elf64Dyn;
        lm.dynamic = dyn_ptr;
        lm.dyn_info = unsafe { dynamic::parse_dynamic(dyn_ptr) };
        unsafe { apply_dyn_info(lm) };

        if lm.dyn_info.soname != 0 && !lm.strtab.is_null() {
            lm.soname = unsafe { lm.strtab.add(lm.dyn_info.soname as usize) };
        }
    }

    if let Some(tls_ph) = header::find_tls_phdr(phdrs) {
        lm.tls_image = load_base as usize + tls_ph.p_vaddr as usize;
        lm.tls_filesz = tls_ph.p_filesz as usize;
        lm.tls_memsz = tls_ph.p_memsz as usize;
        lm.tls_align = tls_ph.p_align as usize;
        // Module ID is assigned by the caller after `tls::register_runtime_module`.
    }

    // Advance the DSO-window cursor past this image so the next load does not
    // collide.
    if st.lib_load_addr <= envelope_end {
        st.lib_load_addr = page_align_up(envelope_end + PAGE_SIZE);
    }

    Ok(lm_val)
}
/// Load a DSO at `path` for dlopen: build its `LinkMap` via
/// [`load_object_into`], mark it runtime-loaded, and link it into the
/// `st.dl_head` chain. Returns the chain entry.
///
/// # Safety
/// Callers must hold `st.dl_lock` during the chain mutation; `path` must be
/// a NUL-terminated byte string.
pub unsafe fn load_object(st: &mut RtldState, path: *const u8) -> Result<*mut LinkMap, LoadError> {
    let mut lm = unsafe { load_object_into(st, path)? };
    lm.set_flag(link_flags::RUNTIME_LOADED);
    lm.refcount = 1;
    let lm_ptr = arena_alloc_link_map(&mut st.arena).ok_or(LoadError::OutOfArena)?;
    unsafe {
        core::ptr::write(lm_ptr, lm);
        (*lm_ptr).l_next = st.dl_head;
        if !st.dl_head.is_null() {
            (*st.dl_head).l_prev = lm_ptr;
        }
    }
    st.dl_head = lm_ptr;
    Ok(lm_ptr)
}

fn chain_next_load_hint(st: &RtldState, size: usize) -> usize {
    if st.lib_load_addr == 0 {
        return 0;
    }
    let candidate = st.lib_load_addr;
    if st.lib_load_limit != 0 && candidate.saturating_add(size) > st.lib_load_limit {
        // No room in the dedicated window — fall back to mmsrv's choice.
        return 0;
    }
    candidate
}

fn cstr_len(s: *const u8) -> usize {
    let mut n = 0usize;
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// Run DT_INIT and DT_INIT_ARRAY exactly once. Idempotent — the
/// `INIT_DONE` flag bit guards re-entry.
///
/// # Safety
/// All non-PLT relocations must already have been applied.
pub unsafe fn run_init(lm: &mut LinkMap) {
    if lm.has_flag(link_flags::INIT_DONE) {
        return;
    }
    if lm.init != 0 {
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(lm.init) };
        unsafe { f() };
    }
    if lm.init_array != 0 && lm.init_arraysz > 0 {
        let arr = lm.init_array as *const unsafe extern "C" fn();
        let count = lm.init_arraysz / core::mem::size_of::<usize>();
        for i in 0..count {
            let f = unsafe { *arr.add(i) };
            unsafe { f() };
        }
    }
    lm.set_flag(link_flags::INIT_DONE);
}

/// Run DT_FINI_ARRAY (reverse) then DT_FINI exactly once.
///
/// # Safety
/// Caller must guarantee the object is no longer reachable from any other
/// LinkMap's symbol scope.
pub unsafe fn run_fini(lm: &mut LinkMap) {
    if lm.has_flag(link_flags::FINI_DONE) {
        return;
    }
    if lm.fini_array != 0 && lm.fini_arraysz > 0 {
        let arr = lm.fini_array as *const unsafe extern "C" fn();
        let count = lm.fini_arraysz / core::mem::size_of::<usize>();
        for i in (0..count).rev() {
            let f = unsafe { *arr.add(i) };
            unsafe { f() };
        }
    }
    if lm.fini != 0 {
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(lm.fini) };
        unsafe { f() };
    }
    lm.set_flag(link_flags::FINI_DONE);
}

/// Unmap a runtime-loaded object's pages. NO-OP for STARTUP objects — they
/// are pinned for process lifetime.
///
/// # Safety
/// Caller must ensure no thread holds a reference into the mapping.
pub unsafe fn unmap_runtime_object(lm: &mut LinkMap) {
    if lm.has_flag(link_flags::STARTUP) || lm.map_start == 0 || lm.map_end <= lm.map_start {
        return;
    }
    // The image's runs were mapped under one mmsrv image reservation; tear the
    // whole envelope down as a unit. A 0 `image_id` (no reservation) falls back
    // to a plain range unmap of the recorded span.
    if lm.image_id != 0 {
        let _ = unsafe { trona_runtime::client::mm::unmap_image(lm.image_id) };
    } else {
        let len = lm.map_end - lm.map_start;
        let _ = unsafe { trona_runtime::client::mm::munmap(lm.map_start as *mut u8, len as u64) };
    }
    lm.map_start = 0;
    lm.map_end = 0;
    lm.image_id = 0;
}
