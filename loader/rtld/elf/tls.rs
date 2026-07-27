//! SPDX-License-Identifier: GPL-2.0-only
//! Runtime TLS module registration and dynamic TLS vector (DTV).
//!
//! The DTV mirrors glibc's per-thread layout: a header followed by an array
//! of `DtvSlot` records indexed by `mod_id - DYNAMIC_TLS_MODULE_BASE`. Each
//! slot lazily acquires its own anonymous mmap when first accessed via
//! [`tls_addr_impl`]. `tls_destroy_impl` walks the slots and unmaps them on
//! thread exit.
//!
//! ## DTV / slab allocation source
//!
//! The plan called for the DTV header and per-module TLS blocks to live in
//! the rtld arena. They live in mmsrv-backed mappings instead, on purpose:
//!
//! - the rtld arena is a process-lifetime bump allocator with no `free`,
//! - the DTV header and every per-module slab are **per-thread** and MUST be
//!   reclaimed on `pthread_exit` (otherwise every short-lived thread that
//!   touches a dlopen'd `__thread` variable leaks page-sized blocks),
//! - per-thread free is exactly what mmsrv unmap gives us.
//!
//! Sharing the arena would force either a leak per thread or a parallel
//! free-list. Per-slab mappings keep the lifetime contract clean.
//! Long-running processes that dlopen many TLS-using modules pay one mmap
//! per (thread, module); the trade is fragmentation versus correctness, and
//! correctness wins here.

use crate::common::elf::tls::DYNAMIC_TLS_MODULE_BASE;
use crate::common::link_map::{LinkMap, RtldState};
use crate::rtld::elf::object;
use crate::rtld::state;
use ::core::sync::atomic::Ordering;
use trona_kernel::core_types::DynamicTlsVector;
use trona_kernel::core_types::ThreadLocalBlock;

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_ANON: i32 = 0x20;
const MAP_PRIV: i32 = 0x02;
const PAGE: usize = 4096;
const DEFAULT_DTV_SLOTS: usize = 32;

/// One DTV slot. `block` is the per-thread TLS storage for the corresponding
/// dynamic module; `size` records the allocation length so [`tls_destroy_impl`]
/// can return it via munmap.
#[repr(C)]
struct DtvSlot {
    block: *mut u8,
    size: usize,
}

/// DTV header — followed in memory by `[DtvSlot; capacity]`.
#[repr(C)]
struct DtvHeader {
    /// Generation counter (glibc-style). Currently unused by SaltyOS but the
    /// slot is kept for ABI parity with future DTV-resize code.
    generation: u64,
    /// Number of `DtvSlot` entries that fit after this header.
    capacity: u32,
    _pad: u32,
}

const DTV_HEADER_BYTES: usize = core::mem::size_of::<DtvHeader>();
const DTV_SLOT_BYTES: usize = core::mem::size_of::<DtvSlot>();

/// Issue a fresh dynamic TLS module ID and stamp it onto the LinkMap. The
/// allocated ID lives strictly above [`DYNAMIC_TLS_MODULE_BASE`] so it never
/// collides with a startup-allocated static module.
pub fn register_runtime_module(st: &mut RtldState, lm: &mut LinkMap) -> u32 {
    let raw = st.next_dynamic_tls_module_id.fetch_add(1, Ordering::AcqRel);
    let id = if raw == 0 {
        // First ever dynamic ID — bump past the boundary.
        st.next_dynamic_tls_module_id
            .store(DYNAMIC_TLS_MODULE_BASE + 1, Ordering::Release);
        DYNAMIC_TLS_MODULE_BASE
    } else if raw < DYNAMIC_TLS_MODULE_BASE {
        // Counter never initialised — clamp.
        st.next_dynamic_tls_module_id
            .store(DYNAMIC_TLS_MODULE_BASE + 1, Ordering::Release);
        DYNAMIC_TLS_MODULE_BASE
    } else {
        raw
    };
    lm.tls_mod_id = id as usize;
    id
}

/// rtld-side entry that satisfies `RtldDlfcnV1::tls_addr`. Static module
/// requests are forwarded to substrate's existing path; dynamic modules are
/// resolved via the per-thread DTV, allocating storage on first touch.
///
/// # Safety
/// Called by libc from arbitrary threads. The function is reentrancy-safe
/// because every mutation of the DTV uses the per-thread block exclusively.
pub unsafe extern "C" fn tls_addr_impl(
    module_id: u64,
    offset: u64,
    _errbuf: *mut u8,
    _errbuf_len: usize,
) -> *mut u8 {
    if (module_id as u32) < DYNAMIC_TLS_MODULE_BASE {
        return unsafe { trona_runtime::thread::tls::tls_addr(module_id, offset) };
    }

    let tcb = match trona_runtime::thread::tls::current_tls() {
        Some(p) => p,
        None => return core::ptr::null_mut(),
    };

    let st = unsafe { state::get_state_ref() };
    let module = match find_runtime_module(st, module_id as u32) {
        Some(m) => m,
        None => return core::ptr::null_mut(),
    };

    let block = unsafe { dtv_slot_block(tcb, module_id as u32, &module) };
    if block.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { block.add(offset as usize) }
}

/// rtld-side entry that satisfies `RtldDlfcnV1::tls_destroy`. Walks the
/// current thread's DTV and frees every allocated block, then frees the DTV
/// itself.
pub unsafe extern "C" fn tls_destroy_impl(_thread_id: u64, _errbuf: *mut u8, _errbuf_len: usize) {
    let tcb = match trona_runtime::thread::tls::current_tls() {
        Some(p) => p,
        None => return,
    };
    let dtv_ptr = unsafe { (*tcb).dynamic_tls } as *mut u8;
    if dtv_ptr.is_null() {
        return;
    }
    let header = unsafe { &*(dtv_ptr as *const DtvHeader) };
    let capacity = header.capacity as usize;
    let slots = unsafe { dtv_ptr.add(DTV_HEADER_BYTES) as *mut DtvSlot };
    for i in 0..capacity {
        let slot = unsafe { &mut *slots.add(i) };
        if !slot.block.is_null() && slot.size > 0 {
            let _ = unsafe { trona_runtime::client::mm::munmap(slot.block, slot.size as u64) };
            slot.block = core::ptr::null_mut();
            slot.size = 0;
        }
    }
    let dtv_bytes = dtv_total_bytes(capacity);
    let _ = unsafe { trona_runtime::client::mm::munmap(dtv_ptr, dtv_bytes as u64) };
    unsafe { (*tcb).dynamic_tls = core::ptr::null_mut() };
}

fn find_runtime_module(st: &RtldState, mod_id: u32) -> Option<ModuleTemplate> {
    let mut cur = st.dl_head;
    while !cur.is_null() {
        let lm = unsafe { &*cur };
        if lm.tls_mod_id as u32 == mod_id {
            return Some(ModuleTemplate {
                template: lm.tls_image,
                filesz: lm.tls_filesz,
                memsz: lm.tls_memsz,
                align: lm.tls_align.max(1),
            });
        }
        cur = lm.l_next;
    }
    None
}

#[derive(Clone, Copy)]
struct ModuleTemplate {
    template: usize,
    filesz: usize,
    memsz: usize,
    align: usize,
}

unsafe fn dtv_slot_block(
    tcb: *mut ThreadLocalBlock,
    mod_id: u32,
    module: &ModuleTemplate,
) -> *mut u8 {
    let dtv = unsafe { ensure_dtv(tcb) };
    if dtv.is_null() {
        return core::ptr::null_mut();
    }
    let header = unsafe { &mut *(dtv as *mut DtvHeader) };
    let slots = unsafe { dtv.add(DTV_HEADER_BYTES) as *mut DtvSlot };
    let slot_idx = (mod_id - DYNAMIC_TLS_MODULE_BASE) as usize;
    if slot_idx >= header.capacity as usize {
        // Capacity overflow — rebuild with a larger DTV.
        let new_cap = (slot_idx + 1).next_power_of_two().max(DEFAULT_DTV_SLOTS);
        if !unsafe { grow_dtv(tcb, new_cap) } {
            return core::ptr::null_mut();
        }
        return unsafe { dtv_slot_block(tcb, mod_id, module) };
    }
    let slot = unsafe { &mut *slots.add(slot_idx) };
    if !slot.block.is_null() {
        return slot.block;
    }

    // Allocate a fresh block, sized to memsz rounded up to align and page.
    let bytes = ((module.memsz + module.align - 1) & !(module.align - 1)).max(1);
    let pages = ((bytes + PAGE - 1) / PAGE) * PAGE;
    let block = unsafe {
        trona_runtime::client::mm::mmap_anonymous(
            core::ptr::null_mut(),
            pages as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIV,
        )
        .unwrap_or(usize::MAX as *mut u8)
    };
    if block as usize == usize::MAX || block.is_null() {
        return core::ptr::null_mut();
    }
    if module.template != 0 && module.filesz > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(module.template as *const u8, block, module.filesz);
        }
    }
    if module.memsz > module.filesz {
        unsafe {
            core::ptr::write_bytes(block.add(module.filesz), 0, module.memsz - module.filesz);
        }
    }
    slot.block = block;
    slot.size = pages;
    block
}

unsafe fn ensure_dtv(tcb: *mut ThreadLocalBlock) -> *mut u8 {
    let cur = unsafe { (*tcb).dynamic_tls } as *mut u8;
    if !cur.is_null() {
        return cur;
    }
    let bytes = dtv_total_bytes(DEFAULT_DTV_SLOTS);
    let raw = unsafe {
        trona_runtime::client::mm::mmap_anonymous(
            core::ptr::null_mut(),
            bytes as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIV,
        )
        .unwrap_or(usize::MAX as *mut u8)
    };
    if raw as usize == usize::MAX || raw.is_null() {
        return core::ptr::null_mut();
    }
    let header = unsafe { &mut *(raw as *mut DtvHeader) };
    header.generation = 1;
    header.capacity = DEFAULT_DTV_SLOTS as u32;
    header._pad = 0;
    unsafe { (*tcb).dynamic_tls = raw as *mut DynamicTlsVector };
    raw
}

unsafe fn grow_dtv(tcb: *mut ThreadLocalBlock, new_capacity: usize) -> bool {
    let old = unsafe { (*tcb).dynamic_tls } as *mut u8;
    if old.is_null() {
        // Just allocate a fresh DTV at the requested capacity.
        let bytes = dtv_total_bytes(new_capacity);
        let raw = unsafe {
            trona_runtime::client::mm::mmap_anonymous(
                core::ptr::null_mut(),
                bytes as u64,
                PROT_READ | PROT_WRITE,
                MAP_ANON | MAP_PRIV,
            )
            .unwrap_or(usize::MAX as *mut u8)
        };
        if raw as usize == usize::MAX || raw.is_null() {
            return false;
        }
        let header = unsafe { &mut *(raw as *mut DtvHeader) };
        header.generation = 1;
        header.capacity = new_capacity as u32;
        header._pad = 0;
        unsafe { (*tcb).dynamic_tls = raw as *mut DynamicTlsVector };
        return true;
    }

    let old_header = unsafe { &*(old as *const DtvHeader) };
    let old_capacity = old_header.capacity as usize;
    let old_generation = old_header.generation;
    let old_bytes = dtv_total_bytes(old_capacity);

    let new_bytes = dtv_total_bytes(new_capacity);
    let new = unsafe {
        trona_runtime::client::mm::mmap_anonymous(
            core::ptr::null_mut(),
            new_bytes as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIV,
        )
        .unwrap_or(usize::MAX as *mut u8)
    };
    if new as usize == usize::MAX || new.is_null() {
        return false;
    }
    let new_header = unsafe { &mut *(new as *mut DtvHeader) };
    new_header.generation = old_generation + 1;
    new_header.capacity = new_capacity as u32;
    new_header._pad = 0;

    // Copy existing slots verbatim — block pointers transfer ownership.
    let copy_slots = old_capacity.min(new_capacity);
    let old_slots = unsafe { old.add(DTV_HEADER_BYTES) as *const DtvSlot };
    let new_slots = unsafe { new.add(DTV_HEADER_BYTES) as *mut DtvSlot };
    for i in 0..copy_slots {
        unsafe {
            new_slots.add(i).write(old_slots.add(i).read());
        }
    }
    for i in copy_slots..new_capacity {
        unsafe {
            new_slots.add(i).write(DtvSlot {
                block: core::ptr::null_mut(),
                size: 0,
            });
        }
    }

    unsafe { (*tcb).dynamic_tls = new as *mut DynamicTlsVector };
    let _ = unsafe { trona_runtime::client::mm::munmap(old, old_bytes as u64) };
    true
}

fn dtv_total_bytes(capacity: usize) -> usize {
    let raw = DTV_HEADER_BYTES + capacity * DTV_SLOT_BYTES;
    (raw + PAGE - 1) & !(PAGE - 1)
}

// `LinkMap` is reached only through the chain walk in `find_runtime_module`.
// The import keeps that lookup honest about its dependency on link map type
// stability across the loader crate.
#[allow(dead_code)]
fn _link_map_used(lm: *const LinkMap) -> usize {
    lm as usize
}

// Re-export the loader's run_init/run_fini so the dlfcn module can pull TLS-
// adjacent lifecycle helpers from one place.
pub use object::{run_fini, run_init};

// ---------------------------------------------------------------------------
// TLSDESC pre-binding (rtld walks each runtime-loaded LinkMap's TLSDESC
// relocs before invoking the generic relocator).
// ---------------------------------------------------------------------------

use crate::common::arch;
use crate::common::elf::types::{elf64_r_sym, elf64_r_type};
use crate::common::link_map::link_flags;

unsafe extern "C" {
    fn _dl_tlsdesc_static_resolver();
    fn _dl_tlsdesc_dynamic_resolver();
}

/// Per-relocation argument the dynamic TLSDESC resolver receives via the
/// descriptor's second word. Allocated in the rtld arena (process-lifetime),
/// shared across every thread that touches the relocation.
#[repr(C)]
pub struct TlsDescDyn {
    pub module_id: u64,
    pub offset: u64,
}

/// Walk every `R_TLSDESC` reloc on `lm` and write the descriptor pair
/// (`resolver_addr`, `arg`) directly. Subsequent calls into
/// `apply_rela_table` skip TLSDESC because they are already bound.
///
/// # Safety
/// `lm` must reference a fully-mapped runtime DSO. Callers hold
/// `RtldState::dl_lock`.
pub unsafe fn bind_tlsdesc(st: &mut RtldState, lm_ptr: *mut LinkMap) -> Result<(), ()> {
    let lm = unsafe { &*lm_ptr };
    let base = lm.base;

    let static_resolver = _dl_tlsdesc_static_resolver as *const () as usize as u64;
    let dynamic_resolver = _dl_tlsdesc_dynamic_resolver as *const () as usize as u64;

    for &(table, count) in &[(lm.rela, lm.rela_count), (lm.jmprel, lm.jmprel_count)] {
        if table.is_null() || count == 0 {
            continue;
        }
        for i in 0..count {
            let r = unsafe { &*table.add(i) };
            if elf64_r_type(r.r_info) != arch::R_TLSDESC {
                continue;
            }
            let target = (base as u64 + r.r_offset) as *mut u64;
            let sym_idx = elf64_r_sym(r.r_info);

            if sym_idx == 0 {
                // Symbol-less form: addend carries the static TP-relative
                // offset directly. Always emits the static resolver.
                unsafe {
                    target.write(static_resolver);
                    target.add(1).write(r.r_addend as u64);
                }
                continue;
            }

            let (mod_id, sym_offset) = match resolve_tls_symbol(st, lm_ptr, sym_idx) {
                Some(v) => v,
                None => continue, // weak unresolved → leave slot zero
            };
            let final_offset = sym_offset + r.r_addend as u64;

            if (mod_id as u32) < DYNAMIC_TLS_MODULE_BASE {
                // Static TLS module — fold the static TP offset into arg
                // and use the static resolver, avoiding a per-thread
                // allocation entirely.
                let tp_off = static_tp_offset(st, mod_id);
                unsafe {
                    target.write(static_resolver);
                    target.add(1).write(tp_off.wrapping_add(final_offset));
                }
            } else {
                let desc = match arena_alloc_tlsdesc_dyn(st, mod_id, final_offset) {
                    Some(p) => p,
                    None => return Err(()),
                };
                unsafe {
                    target.write(dynamic_resolver);
                    target.add(1).write(desc as u64);
                }
            }
        }
    }
    Ok(())
}

/// Look up a TLS-typed symbol across the loaded chain, returning the
/// owning module ID and the symbol's offset within that module.
fn resolve_tls_symbol(
    st: &RtldState,
    requesting: *const LinkMap,
    sym_idx: u32,
) -> Option<(u64, u64)> {
    let req = unsafe { &*requesting };
    let sym = unsafe { &*req.symtab.add(sym_idx as usize) };
    if sym.st_name == 0 {
        return None;
    }
    let name_ptr = unsafe { req.strtab.add(sym.st_name as usize) };
    let mut len = 0usize;
    while unsafe { *name_ptr.add(len) } != 0 {
        len += 1;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, len) };

    // Searching: own object first (TLS variable might be defined here),
    // then seed objects, then RTLD_GLOBAL chain entries.
    if let Some(off) = lookup_tls_in(unsafe { &*requesting }, name) {
        return Some((req.tls_mod_id as u64, off));
    }
    for i in 0..st.count {
        let lm = &st.objects[i];
        if !core::ptr::eq(lm as *const LinkMap, requesting)
            && let Some(off) = lookup_tls_in(lm, name)
        {
            return Some((lm.tls_mod_id as u64, off));
        }
    }
    let mut cur = st.dl_head;
    while !cur.is_null() {
        let lm = unsafe { &*cur };
        if !core::ptr::eq(cur as *const LinkMap, requesting)
            && lm.has_flag(link_flags::RTLD_GLOBAL)
            && let Some(off) = lookup_tls_in(lm, name)
        {
            return Some((lm.tls_mod_id as u64, off));
        }
        cur = lm.l_next;
    }
    None
}

fn lookup_tls_in(lm: &LinkMap, name: &[u8]) -> Option<u64> {
    if lm.symtab.is_null() || lm.strtab.is_null() {
        return None;
    }
    let count = object::sym_count(lm);
    for i in 0..count {
        let sym = unsafe { &*lm.symtab.add(i) };
        if crate::common::elf::types::elf64_st_type(sym.st_info)
            != crate::common::elf::types::STT_TLS
        {
            continue;
        }
        let s = unsafe { lm.strtab.add(sym.st_name as usize) };
        let mut j = 0usize;
        let mut hit = true;
        while j < name.len() {
            if unsafe { *s.add(j) } != name[j] {
                hit = false;
                break;
            }
            j += 1;
        }
        if hit && unsafe { *s.add(name.len()) } == 0 {
            return Some(sym.st_value);
        }
    }
    None
}

fn static_tp_offset(st: &RtldState, mod_id: u64) -> u64 {
    for tm in st.tls_modules.iter() {
        if tm.mod_id as u64 == mod_id {
            return tm.offset as u64;
        }
    }
    0
}

fn arena_alloc_tlsdesc_dyn(
    st: &mut RtldState,
    module_id: u64,
    offset: u64,
) -> Option<*mut TlsDescDyn> {
    let p = object::arena_alloc(
        &mut st.arena,
        core::mem::size_of::<TlsDescDyn>(),
        core::mem::align_of::<TlsDescDyn>(),
    )? as *mut TlsDescDyn;
    unsafe {
        core::ptr::write(p, TlsDescDyn { module_id, offset });
    }
    Some(p)
}

/// TLSDESC dynamic resolver — invoked from the per-arch trampoline. Returns
/// the TP-relative offset of the variable described by `arg`. The compiler-
/// emitted callsite adds TP to the result to obtain the final address.
///
/// # Safety
/// `arg` MUST point to a valid `TlsDescDyn` allocated by [`bind_tlsdesc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rtld_tlsdesc_resolve_dynamic(arg: *const TlsDescDyn) -> usize {
    if arg.is_null() {
        return 0;
    }
    let dyn_arg = unsafe { &*arg };
    let var_addr =
        unsafe { tls_addr_impl(dyn_arg.module_id, dyn_arg.offset, core::ptr::null_mut(), 0) };
    if var_addr.is_null() {
        return 0;
    }
    let tp = unsafe { trona_runtime::thread::tls::read_tp() } as usize;
    (var_addr as usize).wrapping_sub(tp)
}
