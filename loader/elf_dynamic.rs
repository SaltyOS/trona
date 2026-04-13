//! ELF dynamic linking helpers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Utilities for inspecting ELF files before loading: detecting the
//! presence of a PT_INTERP segment (runtime linker), extracting its
//! path, listing DT_NEEDED shared library dependencies, and reading
//! program header info for the auxiliary vector.

use trona::consts::kernel::*;
use trona::types::core::*;

// ---- CPIO initrd library path helpers ----

/// CPIO initrd library path prefix.
/// All shared libraries are stored as "lib/<soname>" in the initrd archive.
pub const INITRD_LIB_PREFIX: &[u8] = b"lib/";

/// Build a CPIO-relative library path from a bare soname.
///
/// Prepends [`INITRD_LIB_PREFIX`] to `soname` and writes the result into `dst`.
/// Returns the number of bytes written, or 0 if `dst` is too small.
///
/// Example: `b"libtrona.so"` → `b"lib/libtrona.so"`
pub fn build_initrd_lib_path(soname: &[u8], dst: &mut [u8]) -> usize {
    let total = INITRD_LIB_PREFIX.len() + soname.len();
    if total > dst.len() {
        return 0;
    }
    dst[..INITRD_LIB_PREFIX.len()].copy_from_slice(INITRD_LIB_PREFIX);
    dst[INITRD_LIB_PREFIX.len()..total].copy_from_slice(soname);
    total
}

/// Default ELF runtime linker soname.
pub const DEFAULT_RTLD_SONAME: &[u8] = b"ld-trona.so";

/// Convert a PT_INTERP string to a CPIO-relative library path.
///
/// Handles all common interp forms:
/// - `/lib/ld-trona.so` → `lib/ld-trona.so` (strip leading `/`)
/// - `lib/ld-trona.so`  → `lib/ld-trona.so` (already CPIO-relative)
/// - `ld-trona.so`      → `lib/ld-trona.so` (prepend `lib/`)
/// - empty              → `lib/ld-trona.so` (default)
///
/// Returns the number of bytes written to `dst`, or 0 if `dst` is too small.
pub fn resolve_interp_to_cpio_path(interp: &[u8], dst: &mut [u8]) -> usize {
    if interp.is_empty() {
        return build_initrd_lib_path(DEFAULT_RTLD_SONAME, dst);
    }

    if interp[0] == b'/' {
        // Absolute path: strip leading '/'
        let stripped = &interp[1..];
        if stripped.len() > dst.len() {
            return 0;
        }
        dst[..stripped.len()].copy_from_slice(stripped);
        stripped.len()
    } else {
        let mut has_slash = false;
        let mut i = 0;
        while i < interp.len() {
            if interp[i] == b'/' {
                has_slash = true;
                break;
            }
            i += 1;
        }
        if has_slash {
            // Already relative with path component: use as-is
            if interp.len() > dst.len() {
                return 0;
            }
            dst[..interp.len()].copy_from_slice(interp);
            interp.len()
        } else {
            // Bare name: prepend "lib/"
            build_initrd_lib_path(interp, dst)
        }
    }
}

/// Check whether an ELF file has a PT_INTERP segment (i.e. needs a runtime linker).
///
/// # Safety
/// `elf_data` must point to a valid ELF file of at least `elf_size` bytes.
pub unsafe fn elf_has_interp(elf_data: *const u8, elf_size: usize) -> bool {
    if elf_size < core::mem::size_of::<Elf64Ehdr>() {
        return false;
    }

    unsafe {
        let ehdr = &*(elf_data as *const Elf64Ehdr);
        let phoff = ehdr.e_phoff as usize;
        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;

        for i in 0..phnum {
            let off = phoff + i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > elf_size {
                break;
            }
            let phdr = &*(elf_data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_INTERP {
                return true;
            }
        }
        false
    }
}

/// Return a pointer to the PT_INTERP string (runtime linker path) within the
/// ELF data, or null if no PT_INTERP segment exists.
///
/// # Safety
/// `elf_data` must point to a valid ELF file of at least `elf_size` bytes.
pub unsafe fn elf_get_interp(elf_data: *const u8, elf_size: usize) -> *const u8 {
    if elf_size < core::mem::size_of::<Elf64Ehdr>() {
        return core::ptr::null();
    }

    unsafe {
        let ehdr = &*(elf_data as *const Elf64Ehdr);
        let phoff = ehdr.e_phoff as usize;
        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;

        for i in 0..phnum {
            let off = phoff + i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > elf_size {
                break;
            }
            let phdr = &*(elf_data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_INTERP {
                let interp_off = phdr.p_offset as usize;
                let interp_len = phdr.p_filesz as usize;
                if interp_off + interp_len > elf_size {
                    return core::ptr::null();
                }
                return elf_data.add(interp_off);
            }
        }
        core::ptr::null()
    }
}

// ---- DT_NEEDED extraction ----

/// Maximum number of DT_NEEDED shared library dependencies tracked.
pub const MAX_NEEDED_LIBS: usize = 12;
/// Maximum length of a DT_NEEDED library name (bytes).
pub const MAX_NEEDED_NAME: usize = 24;

/// Collection of DT_NEEDED library names extracted from an ELF binary.
#[derive(Clone, Copy)]
pub struct NeededLibs {
    pub count: usize,
    pub names: [[u8; MAX_NEEDED_NAME]; MAX_NEEDED_LIBS],
    pub name_lens: [usize; MAX_NEEDED_LIBS],
}

impl NeededLibs {
    pub const fn new() -> Self {
        NeededLibs {
            count: 0,
            names: [[0u8; MAX_NEEDED_NAME]; MAX_NEEDED_LIBS],
            name_lens: [0; MAX_NEEDED_LIBS],
        }
    }

    /// Add a library name to the needed list.  Returns false if full.
    pub fn add(&mut self, name: &[u8]) -> bool {
        if self.count >= MAX_NEEDED_LIBS {
            return false;
        }
        let copy_len = if name.len() > MAX_NEEDED_NAME { MAX_NEEDED_NAME } else { name.len() };
        let idx = self.count;
        for j in 0..copy_len {
            self.names[idx][j] = name[j];
        }
        self.name_lens[idx] = copy_len;
        self.count += 1;
        true
    }

    /// Check if a library name is in the needed list.
    pub fn contains(&self, name: &[u8]) -> bool {
        for i in 0..self.count {
            if self.name_lens[i] == name.len() {
                let mut eq = true;
                for j in 0..name.len() {
                    if self.names[i][j] != name[j] {
                        eq = false;
                        break;
                    }
                }
                if eq {
                    return true;
                }
            }
        }
        false
    }
}

/// Convert a virtual address to a file offset using PT_LOAD segments.
unsafe fn elf_va_to_file_offset(elf_data: *const u8, elf_size: usize, va: u64) -> Option<usize> {
    unsafe {
        let ehdr = &*(elf_data as *const Elf64Ehdr);
        let phoff = ehdr.e_phoff as usize;
        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;

        for i in 0..phnum {
            let off = phoff + i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > elf_size {
                break;
            }
            let phdr = &*(elf_data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_LOAD {
                if va >= phdr.p_vaddr && va < phdr.p_vaddr + phdr.p_filesz {
                    let offset = (va - phdr.p_vaddr + phdr.p_offset) as usize;
                    if offset < elf_size {
                        return Some(offset);
                    }
                }
            }
        }
        None
    }
}

/// Compute the ELF virtual address of the program-header table and the minimum
/// PT_LOAD virtual address for an image.
///
/// Prefer PT_PHDR when present. Otherwise, locate the PT_LOAD segment that
/// contains the on-disk program-header table at `e_phoff`.
unsafe fn elf_compute_phdr_elf_vaddr(
    phdr_ptr: *const u8,
    phnum: usize,
    phentsz: usize,
    phdr_bytes_len: usize,
    e_phoff: u64,
) -> Option<(u64, u64)> {
    unsafe {
        let phdr_table_size = phnum.checked_mul(phentsz)? as u64;
        let phdr_file_end = e_phoff.checked_add(phdr_table_size)?;
        let mut min_load_vaddr = u64::MAX;
        let mut pt_phdr_vaddr = None;
        let mut load_mapped_phdr_vaddr = None;

        for i in 0..phnum {
            let off = i.checked_mul(phentsz)?;
            if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                break;
            }

            let phdr = &*(phdr_ptr.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_LOAD {
                if phdr.p_vaddr < min_load_vaddr {
                    min_load_vaddr = phdr.p_vaddr;
                }

                let seg_file_end = phdr.p_offset.checked_add(phdr.p_filesz)?;
                if e_phoff >= phdr.p_offset && phdr_file_end <= seg_file_end {
                    load_mapped_phdr_vaddr = Some(
                        phdr.p_vaddr.wrapping_add(e_phoff.wrapping_sub(phdr.p_offset)),
                    );
                }
            } else if phdr.p_type == PT_PHDR {
                pt_phdr_vaddr = Some(phdr.p_vaddr);
            }
        }

        if min_load_vaddr == u64::MAX {
            return None;
        }

        Some((pt_phdr_vaddr.or(load_mapped_phdr_vaddr)?, min_load_vaddr))
    }
}

/// Return the PHDR table offset from the image load base.
///
/// For ET_DYN this is the value that should be added to the chosen load base to
/// produce AT_PHDR. For ET_EXEC it likewise yields the mapped PHDR address
/// relative to the lowest PT_LOAD virtual address.
///
/// # Safety
/// `phdr_ptr` must point to at least `phdr_bytes_len` readable bytes containing
/// the ELF program-header table.
pub unsafe fn elf_get_phdr_load_offset(
    phdr_ptr: *const u8,
    phnum: usize,
    phentsz: usize,
    phdr_bytes_len: usize,
    e_phoff: u64,
) -> Option<u64> {
    unsafe {
        let (phdr_elf_vaddr, min_load_vaddr) =
            elf_compute_phdr_elf_vaddr(phdr_ptr, phnum, phentsz, phdr_bytes_len, e_phoff)?;
        Some(phdr_elf_vaddr.wrapping_sub(min_load_vaddr))
    }
}

/// Extract DT_NEEDED library names from a raw (on-disk) ELF file.
///
/// # Safety
/// `elf_data` must point to a valid ELF file of at least `elf_size` bytes.
pub unsafe fn elf_get_needed(elf_data: *const u8, elf_size: usize) -> NeededLibs {
    let mut result = NeededLibs::new();

    unsafe {
        if elf_size < core::mem::size_of::<Elf64Ehdr>() {
            return result;
        }

        let ehdr = &*(elf_data as *const Elf64Ehdr);
        let phoff = ehdr.e_phoff as usize;
        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;

        // Find PT_DYNAMIC
        let mut dyn_offset: usize = 0;
        let mut dyn_size: usize = 0;
        for i in 0..phnum {
            let off = phoff + i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > elf_size {
                break;
            }
            let phdr = &*(elf_data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_DYNAMIC {
                dyn_offset = phdr.p_offset as usize;
                dyn_size = phdr.p_filesz as usize;
                break;
            }
        }
        if dyn_offset == 0 || dyn_offset + dyn_size > elf_size {
            return result;
        }

        let dyn_ptr = elf_data.add(dyn_offset) as *const Elf64Dyn;
        let dyn_count = dyn_size / core::mem::size_of::<Elf64Dyn>();

        // First pass: find DT_STRTAB virtual address
        let mut strtab_va: u64 = 0;
        for i in 0..dyn_count {
            let d = &*dyn_ptr.add(i);
            if d.d_tag == DT_NULL {
                break;
            }
            if d.d_tag == DT_STRTAB {
                strtab_va = d.d_val;
                break;
            }
        }
        if strtab_va == 0 {
            return result;
        }

        // Convert strtab VA to file offset
        let strtab_file_off = match elf_va_to_file_offset(elf_data, elf_size, strtab_va) {
            Some(off) => off,
            None => return result,
        };

        // Second pass: extract DT_NEEDED names
        for i in 0..dyn_count {
            let d = &*dyn_ptr.add(i);
            if d.d_tag == DT_NULL {
                break;
            }
            if d.d_tag == DT_NEEDED {
                let name_off = strtab_file_off + d.d_val as usize;
                if name_off >= elf_size {
                    continue;
                }

                // Read null-terminated name
                let name_ptr = elf_data.add(name_off);
                let mut len = 0usize;
                while name_off + len < elf_size && *name_ptr.add(len) != 0 {
                    len += 1;
                }

                if len > 0 && result.count < MAX_NEEDED_LIBS {
                    let copy_len = if len > MAX_NEEDED_NAME { MAX_NEEDED_NAME } else { len };
                    for j in 0..copy_len {
                        result.names[result.count][j] = *name_ptr.add(j);
                    }
                    result.name_lens[result.count] = copy_len;
                    result.count += 1;
                }
            }
        }
    }

    result
}

/// Extract the mapped program-header table location for the auxiliary vector.
///
/// Writes the absolute AT_PHDR address, entry size, and count into the output
/// pointers. Returns 0 on success, -1 on error.
///
/// # Safety
/// `elf_data` must point to a valid ELF file of at least `elf_size` bytes.
/// Output pointers must be valid and non-null.
pub unsafe fn elf_get_phdr_info(
    elf_data: *const u8,
    elf_size: usize,
    load_base: u64,
    phdr_vaddr: *mut u64,
    phent: *mut u64,
    phnum: *mut u64,
) -> i32 {
    if elf_size < core::mem::size_of::<Elf64Ehdr>() {
        return -1;
    }

    unsafe {
        let ehdr = &*(elf_data as *const Elf64Ehdr);
        let phoff = ehdr.e_phoff as usize;
        let phnum_usize = ehdr.e_phnum as usize;
        let phentsz_usize = ehdr.e_phentsize as usize;
        let phdr_bytes_len = match phnum_usize.checked_mul(phentsz_usize) {
            Some(v) => v,
            None => return -1,
        };
        if phdr_bytes_len == 0 || phoff + phdr_bytes_len > elf_size {
            return -1;
        }

        let load_off = match elf_get_phdr_load_offset(
            elf_data.add(phoff),
            phnum_usize,
            phentsz_usize,
            phdr_bytes_len,
            ehdr.e_phoff,
        ) {
            Some(v) => v,
            None => return -1,
        };
        *phdr_vaddr = load_base.wrapping_add(load_off);
        *phent = ehdr.e_phentsize as u64;
        *phnum = ehdr.e_phnum as u64;
    }
    0
}

// ---- Shared library ELF info extraction ----

/// Basic layout information for an ELF shared library,
/// computed from its PT_LOAD segments.
#[derive(Clone, Copy)]
pub struct ElfLibInfo {
    /// Lowest virtual address across all PT_LOAD segments (page-aligned down).
    pub min_vaddr: u64,
    /// Total virtual memory span (max_seg_end - min_vaddr_aligned).
    pub lib_span: u64,
    /// Number of program headers.
    pub phnum: u16,
}

/// Validate an ELF shared library and compute its VA layout.
///
/// Checks magic bytes and `ET_DYN` type, then walks PT_LOAD segments
/// to determine `min_vaddr` and `lib_span`.
///
/// # Safety
/// `elf_data` must point to at least `elf_size` readable bytes.
pub unsafe fn elf_compute_lib_info(
    elf_data: *const u8,
    elf_size: usize,
) -> Option<ElfLibInfo> {
    if elf_size < core::mem::size_of::<Elf64Ehdr>() {
        return None;
    }

    unsafe {
        let ehdr = &*(elf_data as *const Elf64Ehdr);
        if ehdr.e_ident[0] != 0x7F
            || ehdr.e_ident[1] != b'E'
            || ehdr.e_ident[2] != b'L'
            || ehdr.e_ident[3] != b'F'
        {
            return None;
        }
        if ehdr.e_type != ET_DYN {
            return None;
        }

        let phoff = ehdr.e_phoff as usize;
        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;

        let mut min_vaddr: u64 = u64::MAX;
        let mut max_seg_end: u64 = 0;

        for i in 0..phnum {
            let off = phoff + i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > elf_size {
                break;
            }
            let ph = &*(elf_data.add(off) as *const Elf64Phdr);
            if ph.p_type == PT_LOAD {
                if ph.p_vaddr < min_vaddr {
                    min_vaddr = ph.p_vaddr;
                }
                let se = (ph.p_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;
                if se > max_seg_end {
                    max_seg_end = se;
                }
            }
        }

        if min_vaddr == u64::MAX {
            return None;
        }

        let min_vaddr_aligned = min_vaddr & !0xFFFu64;
        Some(ElfLibInfo {
            min_vaddr,
            lib_span: max_seg_end - min_vaddr_aligned,
            phnum: ehdr.e_phnum,
        })
    }
}
