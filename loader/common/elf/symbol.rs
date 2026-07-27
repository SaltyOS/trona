//! SPDX-License-Identifier: GPL-2.0-only
//! ELF symbol lookup (GNU hash + linear fallback) with optional GNU
//! symbol-versioning support.

use super::types::*;

/// Version-checking context handed to the lookup helpers when the loaded
/// object carries DT_VERSYM / DT_VERDEF metadata.
///
/// `versym` MUST point to a `u16` array indexed by symbol number with at
/// least as many entries as the symbol table. `verdef` (when non-null) MUST
/// point to a chain of `Elf64Verdef` records terminated by a record with
/// `vd_next == 0`. `required` carries an explicit version request: `Some(s)`
/// means "match this version name exactly" (e.g. `dlvsym`), and `None` means
/// "use the default — any non-HIDDEN symbol".
#[derive(Clone, Copy)]
pub struct VersionCheck<'a> {
    pub versym: *const u16,
    pub verdef: *const u8,
    pub strtab: *const u8,
    pub required: Option<&'a [u8]>,
}

/// GNU hash table header, laid out in memory as:
///   u32 nbuckets
///   u32 symoffset    (index of first symbol in chains)
///   u32 bloom_size   (number of bloom filter words)
///   u32 bloom_shift
///   u64[bloom_size]  bloom filter
///   u32[nbuckets]    buckets
///   u32[]            chains (one per symbol starting from symoffset)
struct GnuHash {
    nbuckets: u32,
    symoffset: u32,
    bloom_size: u32,
    bloom_shift: u32,
}

/// Computes the GNU hash of a symbol name.
pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

/// Looks up a symbol by name using the GNU hash table.
///
/// Returns the first defined (`st_shndx != SHN_UNDEF`) symbol whose name
/// matches `name` and whose version satisfies `version_check`.
///
/// # Safety
/// All pointers must reference valid, mapped ELF data structures.
pub unsafe fn gnu_hash_lookup(
    gnu_hash_ptr: *const u32,
    symtab: *const Elf64Sym,
    strtab: *const u8,
    name: &[u8],
    version_check: Option<&VersionCheck<'_>>,
) -> Option<&'static Elf64Sym> {
    let hdr = unsafe { &*(gnu_hash_ptr as *const GnuHash) };
    let nbuckets = hdr.nbuckets;
    let symoffset = hdr.symoffset;
    let bloom_size = hdr.bloom_size;
    let bloom_shift = hdr.bloom_shift;

    if nbuckets == 0 {
        return None;
    }

    let hash = gnu_hash(name);

    // Bloom filter check
    let bloom = unsafe { (gnu_hash_ptr as *const u64).add(2) }; // skip 4×u32 = 16 bytes = 2×u64
    let word_idx = (hash as usize / 64) % bloom_size as usize;
    let bloom_word = unsafe { *bloom.add(word_idx) };
    let bit1 = 1u64 << (hash as u64 % 64);
    let bit2 = 1u64 << ((hash >> bloom_shift) as u64 % 64);
    if (bloom_word & bit1) == 0 || (bloom_word & bit2) == 0 {
        return None;
    }

    // Bucket lookup
    let buckets = unsafe { (bloom.add(bloom_size as usize)) as *const u32 };
    let bucket = hash % nbuckets;
    let sym_idx = unsafe { *buckets.add(bucket as usize) };
    if sym_idx == 0 {
        return None;
    }

    // Chain walk
    let chains = unsafe { buckets.add(nbuckets as usize) };
    let mut idx = sym_idx;
    loop {
        let chain_val = unsafe { *chains.add((idx - symoffset) as usize) };
        // Compare hash (low 31 bits must match)
        if (chain_val | 1) == (hash | 1) {
            let sym = unsafe { &*symtab.add(idx as usize) };
            if unsafe { sym_name_eq(strtab, sym.st_name, name) }
                && sym.st_shndx != SHN_UNDEF
                && unsafe { version_satisfies(version_check, idx) }
            {
                return Some(sym);
            }
        }
        // End of chain? (bit 0 set)
        if chain_val & 1 != 0 {
            break;
        }
        idx += 1;
    }

    None
}

/// Linear symbol table search as fallback when no GNU hash is available.
///
/// # Safety
/// All pointers must reference valid ELF data structures.
pub unsafe fn linear_lookup(
    symtab: *const Elf64Sym,
    sym_count: usize,
    strtab: *const u8,
    name: &[u8],
    version_check: Option<&VersionCheck<'_>>,
) -> Option<&'static Elf64Sym> {
    for i in 0..sym_count {
        let sym = unsafe { &*symtab.add(i) };
        if sym.st_shndx == SHN_UNDEF {
            continue;
        }
        if unsafe { sym_name_eq(strtab, sym.st_name, name) }
            && unsafe { version_satisfies(version_check, i as u32) }
        {
            return Some(sym);
        }
    }
    None
}

/// Convenience wrapper that picks `gnu_hash_lookup` when a GNU hash table is
/// available and falls back to `linear_lookup` otherwise. Versioning rules
/// apply identically to both backends.
///
/// # Safety
/// All non-null pointers must be valid for the lifetime of the call.
pub unsafe fn lookup_symbol_versioned(
    gnu_hash_ptr: *const u32,
    symtab: *const Elf64Sym,
    sym_count: usize,
    strtab: *const u8,
    name: &[u8],
    version_check: Option<&VersionCheck<'_>>,
) -> Option<&'static Elf64Sym> {
    if !gnu_hash_ptr.is_null() {
        unsafe { gnu_hash_lookup(gnu_hash_ptr, symtab, strtab, name, version_check) }
    } else {
        unsafe { linear_lookup(symtab, sym_count, strtab, name, version_check) }
    }
}

/// Checks whether the symbol's name in the string table matches `name`.
unsafe fn sym_name_eq(strtab: *const u8, st_name: u32, name: &[u8]) -> bool {
    let s = unsafe { strtab.add(st_name as usize) };
    for (i, &b) in name.iter().enumerate() {
        if unsafe { *s.add(i) } != b {
            return false;
        }
    }
    // Ensure the string table entry is null-terminated at the right place
    let terminator = unsafe { *s.add(name.len()) };
    terminator == 0
}

/// Decide whether the symbol at index `sym_idx` is acceptable under the
/// caller's version policy. Returns `true` when no policy applies, or when
/// the version index found in `versym[sym_idx]` matches.
///
/// # Safety
/// `version_check.versym` (when present) must be valid for at least
/// `sym_idx + 1` `u16` reads. `verdef` (when present) must be a valid chain.
unsafe fn version_satisfies(check: Option<&VersionCheck<'_>>, sym_idx: u32) -> bool {
    let Some(ctx) = check else {
        return true;
    };
    if ctx.versym.is_null() {
        return ctx.required.is_none();
    }
    let raw = unsafe { *ctx.versym.add(sym_idx as usize) };
    let hidden = raw & VERSYM_HIDDEN != 0;
    let ver_idx = raw & VERSYM_VERSION;

    match ctx.required {
        None => {
            // Default lookup: accept any non-hidden symbol. Hidden symbols
            // require an explicit version request.
            if hidden {
                return false;
            }
            // VER_NDX_LOCAL means strictly local — never bind globally.
            ver_idx != VER_NDX_LOCAL
        }
        Some(want) => {
            // Explicit version request: name from verdef must equal `want`.
            if ctx.verdef.is_null() {
                // No verdef table — fall back to accepting global default.
                return ver_idx == VER_NDX_GLOBAL;
            }
            unsafe { verdef_name_eq(ctx.verdef, ctx.strtab, ver_idx, want) }
        }
    }
}

/// Walk the verdef chain looking for a record whose `vd_ndx` equals
/// `target_idx`, then compare its first `Elf64Verdaux` name to `want`.
///
/// # Safety
/// `verdef` must be a valid `Elf64Verdef` chain terminated by `vd_next == 0`.
unsafe fn verdef_name_eq(
    verdef: *const u8,
    strtab: *const u8,
    target_idx: u16,
    want: &[u8],
) -> bool {
    let mut cur = verdef;
    loop {
        let vd = unsafe { &*(cur as *const Elf64Verdef) };
        if vd.vd_ndx == target_idx && vd.vd_cnt > 0 && vd.vd_aux != 0 {
            let aux_ptr = unsafe { cur.add(vd.vd_aux as usize) } as *const Elf64Verdaux;
            let aux = unsafe { &*aux_ptr };
            if unsafe { cstr_eq(strtab, aux.vda_name, want) } {
                return true;
            }
        }
        if vd.vd_next == 0 {
            return false;
        }
        cur = unsafe { cur.add(vd.vd_next as usize) };
    }
}

/// Compare a NUL-terminated C string at `strtab[off]` against `want`.
unsafe fn cstr_eq(strtab: *const u8, off: u32, want: &[u8]) -> bool {
    let s = unsafe { strtab.add(off as usize) };
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *s.add(i) } != b {
            return false;
        }
    }
    unsafe { *s.add(want.len()) == 0 }
}

/// Walk the requesting object's `DT_VERNEED` chain looking for the version
/// auxiliary record whose `vna_other` equals `ver_idx`. When found, return
/// the version name as a NUL-terminated byte slice from the requesting
/// object's strtab. Used when relocating a reference whose `versym[idx]`
/// points at a versioned import: the returned name becomes the `required`
/// field of [`VersionCheck`] when looking up the symbol in candidate
/// providers.
///
/// # Safety
/// `verneed` must be a valid chain of `Elf64Verneed` records terminated by
/// `vn_next == 0`; `strtab` must cover every `vna_name` offset reachable
/// from the chain.
pub unsafe fn verneed_required_name<'a>(
    verneed: *const u8,
    verneed_num: u32,
    strtab: *const u8,
    ver_idx: u16,
) -> Option<&'a [u8]> {
    if verneed.is_null() || verneed_num == 0 || strtab.is_null() {
        return None;
    }
    let mut cur = verneed;
    for _ in 0..verneed_num {
        let vn = unsafe { &*(cur as *const Elf64Verneed) };
        if vn.vn_aux != 0 {
            let mut aux_cur = unsafe { cur.add(vn.vn_aux as usize) };
            for _ in 0..vn.vn_cnt {
                let vna = unsafe { &*(aux_cur as *const Elf64Vernaux) };
                if vna.vna_other == ver_idx {
                    let name_ptr = unsafe { strtab.add(vna.vna_name as usize) };
                    let mut len = 0usize;
                    while unsafe { *name_ptr.add(len) } != 0 {
                        len += 1;
                    }
                    return Some(unsafe { core::slice::from_raw_parts(name_ptr, len) });
                }
                if vna.vna_next == 0 {
                    break;
                }
                aux_cur = unsafe { aux_cur.add(vna.vna_next as usize) };
            }
        }
        if vn.vn_next == 0 {
            return None;
        }
        cur = unsafe { cur.add(vn.vn_next as usize) };
    }
    None
}

/// Read `versym[sym_idx]` masked to its version-index bits. Returns `None`
/// when no versym table is available.
///
/// # Safety
/// `versym` (when non-null) must be valid for at least `sym_idx + 1` reads.
pub unsafe fn versym_index(versym: *const u16, sym_idx: u32) -> Option<u16> {
    if versym.is_null() {
        return None;
    }
    let raw = unsafe { *versym.add(sym_idx as usize) };
    Some(raw & VERSYM_VERSION)
}
