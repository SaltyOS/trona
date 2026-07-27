//! SPDX-License-Identifier: GPL-2.0-only
//! Symbol scope semantics for the dlfcn surface.
//!
//! The rtld owns three concepts of scope:
//! - **Global**: visible to subsequent dlopen lookups. Includes all startup
//!   objects plus any runtime DSO opened with `RTLD_GLOBAL`.
//! - **Local**: visible only via the dlopen handle that produced it. Plus the
//!   transitive `DT_NEEDED` closure of that handle.
//! - **Next**: the same global chain, started immediately after the LinkMap
//!   that contains the caller PC (RTLD_NEXT semantics).

use crate::common::elf::symbol;
use crate::common::elf::types::*;
use crate::common::link_map::{LinkMap, RtldState, link_flags};
use crate::rtld::elf::object;

/// Categorical scope marker stored on dlopen handles.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    Global,
    Local,
    Nodelete,
}

impl Scope {
    pub fn from_flags(flags: i32) -> Self {
        const RTLD_GLOBAL_FLAG: i32 = 0x0100;
        const RTLD_NODELETE_FLAG: i32 = 0x1000;
        if flags & RTLD_NODELETE_FLAG != 0 {
            Scope::Nodelete
        } else if flags & RTLD_GLOBAL_FLAG != 0 {
            Scope::Global
        } else {
            Scope::Local
        }
    }
}

/// Look up `sym_idx` in the symbol table of `requesting`, then resolve
/// across the global scope (boot-time `objects[1..count]`, including the
/// requesting object at its load-order position, followed by dlopen chain
/// entries flagged `RTLD_GLOBAL`, then rtld itself in slot 0).
///
/// When the requesting object carries DT_VERSYM + DT_VERNEED, the version
/// index for `sym_idx` is resolved into a version name and passed down as
/// the `required` field of [`symbol::VersionCheck`] so providers can match
/// the exact symbol version.
///
/// Used by the startup linker. Falls back to weak-as-zero when the symbol
/// is undefined and weak.
pub fn resolve_symbol_global(st: &RtldState, requesting: usize, sym_idx: u32) -> Option<u64> {
    let obj = &st.objects[requesting];
    let sym = unsafe { &*obj.symtab.add(sym_idx as usize) };
    if sym.st_name == 0 {
        return Some(0);
    }

    let bind = elf64_st_bind(sym.st_info);
    let visibility = elf64_st_visibility(sym.st_other);
    if sym.st_shndx != SHN_UNDEF
        && (bind == STB_LOCAL || visibility == STV_HIDDEN || visibility == STV_PROTECTED)
    {
        return Some(obj.base as u64 + sym.st_value);
    }

    let name = symbol_name(obj, sym.st_name);
    let required = required_version_for(obj, sym_idx);
    if let Some(addr) = lookup_in_global_seed(st, name, required) {
        return Some(addr);
    }
    if let Some(addr) = lookup_in_global_chain(st, name, required) {
        return Some(addr);
    }
    if let Some(addr) = lookup_one(&st.objects[0], name, required) {
        return Some(addr);
    }

    if bind == STB_WEAK {
        return Some(0);
    }
    None
}

/// Resolve `sym_idx` from a runtime-loaded `LinkMap`. Differs from
/// [`resolve_symbol_global`] in that the requesting object is identified by
/// pointer (it lives in the chain, not the seed array) and the seed
/// `objects[1..]` slice is searched first to give startup-loaded libraries
/// priority over later-loaded copies.
pub fn resolve_symbol_for_runtime(
    st: &RtldState,
    requesting: *const LinkMap,
    sym_idx: u32,
) -> Option<u64> {
    let obj = unsafe { &*requesting };
    let sym = unsafe { &*obj.symtab.add(sym_idx as usize) };
    if sym.st_name == 0 {
        return Some(0);
    }

    let bind = elf64_st_bind(sym.st_info);
    let visibility = elf64_st_visibility(sym.st_other);
    if sym.st_shndx != SHN_UNDEF
        && (bind == STB_LOCAL || visibility == STV_HIDDEN || visibility == STV_PROTECTED)
    {
        return Some(obj.base as u64 + sym.st_value);
    }

    let name = symbol_name(obj, sym.st_name);
    let required = required_version_for(obj, sym_idx);

    // Startup objects first, skipping rtld at slot 0.
    for i in 1..st.count {
        if let Some(addr) = lookup_one(&st.objects[i], name, required) {
            return Some(addr);
        }
    }
    // Then walk the chain (which includes RTLD_GLOBAL runtime objects).
    if let Some(addr) = lookup_in_global_chain(st, name, required) {
        return Some(addr);
    }
    // A runtime object must also see its own DT_NEEDED closure even when a
    // dependency was previously loaded with RTLD_LOCAL. This is the normal
    // dlopen local-scope case: the dependency is not globally visible, but
    // it is still part of the requesting object's relocation scope.
    if let Some(addr) = lookup_in_runtime_deps(obj, name, required) {
        return Some(addr);
    }
    if let Some(addr) = lookup_one(obj, name, required) {
        return Some(addr);
    }
    // Finally rtld itself.
    if let Some(addr) = lookup_one(&st.objects[0], name, required) {
        return Some(addr);
    }

    if bind == STB_WEAK {
        return Some(0);
    }
    None
}

/// For the requesting object `obj`, decode `versym[sym_idx]` and look the
/// resulting version index up in the object's verneed table. Returns the
/// version name when the symbol has a versioned import requirement;
/// returns `None` otherwise (no versym, base / global / local index, or no
/// matching aux record). The borrowed slice lives as long as the strtab
/// pointer the requester carries.
fn required_version_for(obj: &LinkMap, sym_idx: u32) -> Option<&'static [u8]> {
    let raw_idx = unsafe { symbol::versym_index(obj.versym, sym_idx) }?;
    if raw_idx <= VER_NDX_GLOBAL {
        // 0 = local, 1 = global/base — neither carries an external
        // version requirement.
        return None;
    }
    unsafe { symbol::verneed_required_name(obj.verneed, obj.verneed_num, obj.strtab, raw_idx) }
}

/// Resolve `name` (NUL-terminated) starting from the LinkMap *after* the one
/// that contains `caller_pc`. Implements `dlsym(RTLD_NEXT, ...)`.
pub fn resolve_next_after(st: &RtldState, caller_pc: usize, name: &[u8]) -> Option<u64> {
    let caller = locate_object_by_pc(st, caller_pc)?;
    let mut found_caller = false;

    // Walk the seed array then the chain, in the same order
    // `resolve_symbol_for_runtime` searches.
    for i in 1..st.count {
        if found_caller && let Some(addr) = lookup_one(&st.objects[i], name, None) {
            return Some(addr);
        }
        if core::ptr::eq(&st.objects[i] as *const LinkMap, caller) {
            found_caller = true;
        }
    }

    let mut cur = st.dl_head;
    while !cur.is_null() {
        let lm = unsafe { &*cur };
        if found_caller
            && lm.has_flag(link_flags::RTLD_GLOBAL)
            && let Some(addr) = lookup_one(lm, name, None)
        {
            return Some(addr);
        }
        if core::ptr::eq(cur as *const LinkMap, caller) {
            found_caller = true;
        }
        cur = lm.l_next;
    }

    if found_caller && let Some(addr) = lookup_one(&st.objects[0], name, None) {
        return Some(addr);
    }
    None
}

/// Resolve `name` for `dlsym(RTLD_DEFAULT, ...)` — the global scope, in
/// load order, with rtld considered last.
pub fn resolve_default(st: &RtldState, name: &[u8]) -> Option<u64> {
    for i in 1..st.count {
        if let Some(addr) = lookup_one(&st.objects[i], name, None) {
            return Some(addr);
        }
    }
    if let Some(addr) = lookup_in_global_chain(st, name, None) {
        return Some(addr);
    }
    lookup_one(&st.objects[0], name, None)
}

/// Resolve `name` strictly within a dlopen handle: the handle's own symbol
/// table first, then the transitive DT_NEEDED set.
pub fn resolve_in_handle(handle: *const LinkMap, name: &[u8]) -> Option<u64> {
    let lm = unsafe { &*handle };
    if let Some(addr) = lookup_one(lm, name, None) {
        return Some(addr);
    }
    lookup_in_runtime_deps(lm, name, None)
}

/// Locate the LinkMap that maps the address `pc`. Returns `None` when no
/// loaded object covers that address.
pub fn locate_object_by_pc(st: &RtldState, pc: usize) -> Option<*const LinkMap> {
    for i in 0..st.count {
        let lm = &st.objects[i];
        if pc_in_object(lm, pc) {
            return Some(lm as *const LinkMap);
        }
    }
    let mut cur = st.dl_head;
    while !cur.is_null() {
        let lm = unsafe { &*cur };
        if pc_in_object(lm, pc) {
            return Some(cur as *const LinkMap);
        }
        cur = lm.l_next;
    }
    None
}

fn pc_in_object(lm: &LinkMap, pc: usize) -> bool {
    if lm.map_start != 0 && lm.map_end > lm.map_start {
        return pc >= lm.map_start && pc < lm.map_end;
    }
    if lm.phdr.is_null() || lm.phnum == 0 {
        return false;
    }
    let phdrs = unsafe { core::slice::from_raw_parts(lm.phdr, lm.phnum as usize) };
    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let lo = lm.base + ph.p_vaddr as usize;
        let hi = lo + ph.p_memsz as usize;
        if pc >= lo && pc < hi {
            return true;
        }
    }
    false
}

fn lookup_in_global_seed(st: &RtldState, name: &[u8], required: Option<&[u8]>) -> Option<u64> {
    for i in 1..st.count {
        if let Some(addr) = lookup_one(&st.objects[i], name, required) {
            return Some(addr);
        }
    }
    None
}

fn lookup_in_global_chain(st: &RtldState, name: &[u8], required: Option<&[u8]>) -> Option<u64> {
    let mut cur = st.dl_head;
    while !cur.is_null() {
        let lm = unsafe { &*cur };
        if lm.has_flag(link_flags::RTLD_GLOBAL)
            && let Some(addr) = lookup_one(lm, name, required)
        {
            return Some(addr);
        }
        cur = lm.l_next;
    }
    None
}

const MAX_RUNTIME_SCOPE_OBJECTS: usize = 64;

fn lookup_in_runtime_deps(root: &LinkMap, name: &[u8], required: Option<&[u8]>) -> Option<u64> {
    let root_ptr = root as *const LinkMap;
    let mut stack: [*const LinkMap; MAX_RUNTIME_SCOPE_OBJECTS] =
        [core::ptr::null(); MAX_RUNTIME_SCOPE_OBJECTS];
    let mut stack_len = 0usize;
    let mut seen: [*const LinkMap; MAX_RUNTIME_SCOPE_OBJECTS] =
        [core::ptr::null(); MAX_RUNTIME_SCOPE_OBJECTS];
    let mut seen_len = 0usize;

    seen[seen_len] = root_ptr;
    seen_len += 1;
    push_deps_reverse(root, &mut stack, &mut stack_len);

    while stack_len > 0 {
        stack_len -= 1;
        let lm_ptr = stack[stack_len];
        if lm_ptr.is_null() || ptr_seen(&seen, seen_len, lm_ptr) {
            continue;
        }
        if seen_len >= MAX_RUNTIME_SCOPE_OBJECTS {
            continue;
        }
        seen[seen_len] = lm_ptr;
        seen_len += 1;

        // SAFETY: `deps_ptr` entries are LinkMap pointers produced by the
        // rtld loader and remain live until the owning dlopen graph is
        // unloaded under `dl_lock`.
        let lm = unsafe { &*lm_ptr };
        if let Some(addr) = lookup_one(lm, name, required) {
            return Some(addr);
        }
        push_deps_reverse(lm, &mut stack, &mut stack_len);
    }

    None
}

fn push_deps_reverse(
    lm: &LinkMap,
    stack: &mut [*const LinkMap; MAX_RUNTIME_SCOPE_OBJECTS],
    stack_len: &mut usize,
) {
    if lm.deps_ptr.is_null() {
        return;
    }
    let mut i = lm.deps_count as usize;
    while i > 0 {
        i -= 1;
        if *stack_len >= MAX_RUNTIME_SCOPE_OBJECTS {
            return;
        }
        // SAFETY: `deps_count` bounds the dependency vector allocated by
        // `load_recursive`, and `deps_ptr` is non-null here.
        let dep = unsafe { *lm.deps_ptr.add(i) };
        stack[*stack_len] = dep as *const LinkMap;
        *stack_len += 1;
    }
}

fn ptr_seen(
    seen: &[*const LinkMap; MAX_RUNTIME_SCOPE_OBJECTS],
    seen_len: usize,
    ptr: *const LinkMap,
) -> bool {
    let mut i = 0usize;
    while i < seen_len {
        if core::ptr::eq(seen[i], ptr) {
            return true;
        }
        i += 1;
    }
    false
}

fn lookup_one(lm: &LinkMap, name: &[u8], required: Option<&[u8]>) -> Option<u64> {
    if lm.symtab.is_null() || lm.strtab.is_null() {
        return None;
    }
    let version_check = build_version_check(lm, required);
    let sym = unsafe {
        symbol::lookup_symbol_versioned(
            lm.gnu_hash,
            lm.symtab,
            object::sym_count(lm),
            lm.strtab,
            name,
            version_check.as_ref(),
        )
    }?;
    Some(lm.base as u64 + sym.st_value)
}

fn build_version_check<'a>(
    lm: &'a LinkMap,
    required: Option<&'a [u8]>,
) -> Option<symbol::VersionCheck<'a>> {
    // Without a versym table on the provider there is nothing to enforce —
    // and if the caller did not supply a required version either, the
    // version-check has no work to do at all.
    if lm.versym.is_null() && required.is_none() {
        return None;
    }
    Some(symbol::VersionCheck {
        versym: lm.versym,
        verdef: lm.verdef,
        strtab: lm.strtab,
        required,
    })
}

fn symbol_name(obj: &LinkMap, st_name: u32) -> &'static [u8] {
    let name_ptr = unsafe { obj.strtab.add(st_name as usize) };
    let mut len = 0usize;
    while unsafe { *name_ptr.add(len) } != 0 {
        len += 1;
    }
    unsafe { core::slice::from_raw_parts(name_ptr, len) }
}
