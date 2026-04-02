//! Userspace PE/COFF loader
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Loads PE32+ (64-bit) executables into a child process's VSpace using
//! the same scratch-map strategy as the ELF loader: each page is temporarily
//! mapped into the loader's own address space, populated with section data,
//! then remapped into the child's VSpace with the correct permissions.
//!
//! Supports:
//! - PE32+ executables (IMAGE_FILE_EXECUTABLE_IMAGE)
//! - PE32+ DLLs (IMAGE_FILE_DLL)
//! - Base relocations (IMAGE_REL_BASED_DIR64)
//! - Import directory parsing (IAT population via callback)
//!
//! Frame allocation uses the same pluggable `ElfLoaderCtx` as the ELF loader.

use trona::consts::kernel::*;
use trona::invoke;
use trona::serial;
use trona::types::core::*;
use trona::types::pe::*;

/// Round down to the nearest 4K page boundary.
fn page_align_down(v: u64) -> u64 {
    v & !(PE_PAGE_SIZE - 1)
}

/// Round up to the next 4K page boundary.
fn page_align_up(v: u64) -> u64 {
    (v + PE_PAGE_SIZE - 1) & !(PE_PAGE_SIZE - 1)
}

/// Maximum number of pages we support for a single PE image.
const MAX_PE_PAGES: usize = 512;

/// Maximum number of sections we support in a PE file.
const MAX_PE_SECTIONS: usize = 32;

/// Maximum number of import DLL entries we track.
pub const MAX_PE_IMPORTS: usize = 16;
/// Maximum length of an import DLL name.
pub const MAX_PE_IMPORT_NAME: usize = 32;

/// Parsed PE header information extracted by `pe_validate`.
#[derive(Clone, Copy)]
pub struct PeInfo {
    /// Offset of the COFF header from the start of the file.
    pub coff_offset: usize,
    /// Machine type (PE_MACHINE_AMD64 or PE_MACHINE_ARM64).
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Size of the optional header.
    pub size_of_optional_header: u16,
    /// COFF characteristics.
    pub characteristics: u16,
    /// Entry point RVA.
    pub entry_point_rva: u32,
    /// Preferred image base.
    pub image_base: u64,
    /// Section alignment (in memory).
    pub section_alignment: u32,
    /// File alignment (on disk).
    pub file_alignment: u32,
    /// Total virtual size of the loaded image.
    pub size_of_image: u32,
    /// Size of all headers (DOS + PE + section headers).
    pub size_of_headers: u32,
    /// Number of data directory entries.
    pub number_of_rva_and_sizes: u32,
    /// Offset of the first section header from file start.
    pub section_headers_offset: usize,
    /// Offset of the data directory array from file start.
    pub data_dir_offset: usize,
}

impl PeInfo {
    pub const fn zeroed() -> Self {
        PeInfo {
            coff_offset: 0,
            machine: 0,
            number_of_sections: 0,
            size_of_optional_header: 0,
            characteristics: 0,
            entry_point_rva: 0,
            image_base: 0,
            section_alignment: 0,
            file_alignment: 0,
            size_of_image: 0,
            size_of_headers: 0,
            number_of_rva_and_sizes: 0,
            section_headers_offset: 0,
            data_dir_offset: 0,
        }
    }
}

/// Collection of import DLL names extracted from a PE binary.
pub struct PeImports {
    pub count: usize,
    pub names: [[u8; MAX_PE_IMPORT_NAME]; MAX_PE_IMPORTS],
    pub name_lens: [usize; MAX_PE_IMPORTS],
}

impl PeImports {
    pub const fn new() -> Self {
        PeImports {
            count: 0,
            names: [[0u8; MAX_PE_IMPORT_NAME]; MAX_PE_IMPORTS],
            name_lens: [0; MAX_PE_IMPORTS],
        }
    }
}

/// Validate a PE file and extract header information.
///
/// Checks the DOS MZ magic, PE signature, PE32+ optional header magic,
/// and machine type. On success, populates `*info` and returns `PE_OK`.
///
/// # Safety
/// `data` must point to a valid buffer of at least `data_len` bytes.
pub unsafe fn pe_validate(data: *const u8, data_len: usize, info: *mut PeInfo) -> i32 {
    unsafe {
        // Need at least a DOS header
        if data_len < core::mem::size_of::<DosHeader>() {
            return PE_TOO_SMALL;
        }

        let dos = &*(data as *const DosHeader);
        if dos.e_magic != PE_DOS_MAGIC {
            return PE_NOT_PE;
        }

        let pe_offset = dos.e_lfanew as usize;

        // PE signature (4 bytes) + COFF header (20 bytes) = minimum 24 bytes after pe_offset
        if pe_offset + 4 + core::mem::size_of::<CoffHeader>() > data_len {
            return PE_TOO_SMALL;
        }

        // Verify PE signature
        let pe_sig = core::ptr::read_unaligned(data.add(pe_offset) as *const u32);
        if pe_sig != PE_SIGNATURE {
            return PE_NOT_PE;
        }

        let coff_offset = pe_offset + 4;
        let coff = &*(data.add(coff_offset) as *const CoffHeader);

        // Validate machine type
        #[cfg(target_arch = "x86_64")]
        if coff.machine != PE_MACHINE_AMD64 {
            return PE_BAD_ARCH;
        }
        #[cfg(target_arch = "aarch64")]
        if coff.machine != PE_MACHINE_ARM64 {
            return PE_BAD_ARCH;
        }

        if coff.number_of_sections == 0 {
            return PE_NO_SECTIONS;
        }

        // Optional header starts right after COFF header
        let opt_offset = coff_offset + core::mem::size_of::<CoffHeader>();
        if opt_offset + core::mem::size_of::<OptionalHeader64>() > data_len {
            return PE_TOO_SMALL;
        }

        let opt = &*(data.add(opt_offset) as *const OptionalHeader64);
        if opt.magic != PE_OPT_MAGIC_PE32PLUS {
            return PE_NOT_64BIT;
        }

        // Data directory starts right after the fixed optional header fields
        let data_dir_offset = opt_offset + core::mem::size_of::<OptionalHeader64>();

        // Section headers start after the optional header
        let section_headers_offset = opt_offset + coff.size_of_optional_header as usize;
        let section_headers_end = section_headers_offset
            + (coff.number_of_sections as usize) * core::mem::size_of::<SectionHeader>();
        if section_headers_end > data_len {
            return PE_TOO_SMALL;
        }

        (*info).coff_offset = coff_offset;
        (*info).machine = coff.machine;
        (*info).number_of_sections = coff.number_of_sections;
        (*info).size_of_optional_header = coff.size_of_optional_header;
        (*info).characteristics = coff.characteristics;
        (*info).entry_point_rva = opt.address_of_entry_point;
        (*info).image_base = opt.image_base;
        (*info).section_alignment = opt.section_alignment;
        (*info).file_alignment = opt.file_alignment;
        (*info).size_of_image = opt.size_of_image;
        (*info).size_of_headers = opt.size_of_headers;
        (*info).number_of_rva_and_sizes = opt.number_of_rva_and_sizes;
        (*info).section_headers_offset = section_headers_offset;
        (*info).data_dir_offset = data_dir_offset;

        PE_OK
    }
}

/// Read a data directory entry at the given index.
///
/// # Safety
/// `data` must be valid for `data_len` bytes. `info` must have been
/// populated by a successful `pe_validate` call.
unsafe fn read_data_dir(
    data: *const u8,
    data_len: usize,
    info: &PeInfo,
    index: usize,
) -> DataDirectory {
    unsafe {
        if index >= info.number_of_rva_and_sizes as usize {
            return DataDirectory::zeroed();
        }
        let entry_offset =
            info.data_dir_offset + index * core::mem::size_of::<DataDirectory>();
        if entry_offset + core::mem::size_of::<DataDirectory>() > data_len {
            return DataDirectory::zeroed();
        }
        core::ptr::read_unaligned(data.add(entry_offset) as *const DataDirectory)
    }
}

/// Convert PE section characteristics to VSpace mapping flags.
/// Enforces W^X: if both WRITE and EXECUTE are set, writable wins.
fn section_to_vspace_flags(characteristics: u32) -> u64 {
    let mut flags = VSPACE_FLAG_USER;
    let w = characteristics & IMAGE_SCN_MEM_WRITE != 0;
    let x = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    if w {
        flags |= VSPACE_FLAG_WRITABLE;
    } else if x {
        flags |= VSPACE_FLAG_EXECUTABLE;
    }
    flags
}

/// Count the number of pages needed to load a PE image.
///
/// # Safety
/// `data` must point to a valid PE file of at least `data_len` bytes.
pub unsafe fn pe_count_load_pages(data: *const u8, data_len: usize) -> usize {
    unsafe {
        let mut info = PeInfo::zeroed();
        if pe_validate(data, data_len, &raw mut info) != PE_OK {
            return 0;
        }
        // The image spans from 0 to size_of_image (all section-aligned)
        let total_size = page_align_up(info.size_of_image as u64);
        (total_size / PE_PAGE_SIZE) as usize
    }
}

/// Compute the total VA span needed to load a PE image.
///
/// # Safety
/// `data` must point to a valid PE file of at least `data_len` bytes.
pub unsafe fn pe_compute_load_span(data: *const u8, data_len: usize) -> u64 {
    unsafe {
        let mut info = PeInfo::zeroed();
        if pe_validate(data, data_len, &raw mut info) != PE_OK {
            return 0;
        }
        page_align_up(info.size_of_image as u64)
    }
}

/// Check whether a buffer starts with the PE/MZ magic bytes.
///
/// # Safety
/// `data` must be valid for at least 2 bytes.
pub unsafe fn pe_is_pe(data: *const u8, data_len: usize) -> bool {
    if data_len < 2 {
        return false;
    }
    unsafe {
        let magic = core::ptr::read_unaligned(data as *const u16);
        magic == PE_DOS_MAGIC
    }
}

/// Tracks a mapped page during PE loading.
#[derive(Clone, Copy)]
struct PePageEntry {
    vaddr: u64,
    frame_cap: Cap,
    flags: u64,
}

/// Load a PE32+ binary into a child process's VSpace.
///
/// Maps the PE headers and each section, allocating frames via `ctx`,
/// copying data via scratch-map, and setting permissions. For relocated
/// images (load_base != image_base), applies base relocations.
///
/// On success, populates `*result` with the entry point, load base, and
/// image end address, and returns `PE_OK`.
///
/// # Safety
/// `data` must point to a valid PE file of at least `data_len` bytes.
/// `ctx` must be a valid `ElfLoaderCtx` (reused for frame allocation).
/// `result` must be a valid pointer.
pub unsafe fn pe_load(
    data: *const u8,
    data_len: usize,
    load_base: u64,
    ctx: &mut ElfLoaderCtx,
    result: *mut PeLoadResult,
) -> i32 {
    unsafe {
        let mut info = PeInfo::zeroed();
        let err = pe_validate(data, data_len, &raw mut info);
        if err != PE_OK {
            return err;
        }

        if info.number_of_sections as usize > MAX_PE_SECTIONS {
            return PE_NO_SECTIONS;
        }

        let delta = load_base.wrapping_sub(info.image_base);
        let image_end = load_base + page_align_up(info.size_of_image as u64);

        let mut pages = [PePageEntry {
            vaddr: 0,
            frame_cap: 0,
            flags: 0,
        }; MAX_PE_PAGES];
        let mut page_count: usize = 0;

        // --- Map PE headers (everything up to size_of_headers) ---
        let headers_end = page_align_up(info.size_of_headers as u64);
        let headers_flags = VSPACE_FLAG_USER; // read-only

        let mut page_vaddr = load_base;
        while page_vaddr < load_base + headers_end {
            let err = map_pe_page(
                data,
                data_len,
                page_vaddr,
                (page_vaddr - load_base) as usize, // file offset = RVA for headers
                PE_PAGE_SIZE as usize,
                headers_flags,
                ctx,
                &mut pages,
                &mut page_count,
            );
            if err != 0 {
                return err;
            }
            page_vaddr += PE_PAGE_SIZE;
        }

        // --- Map each section ---
        let section_base = data.add(info.section_headers_offset);
        for i in 0..info.number_of_sections as usize {
            let sec_offset = i * core::mem::size_of::<SectionHeader>();
            if info.section_headers_offset + sec_offset + core::mem::size_of::<SectionHeader>()
                > data_len
            {
                break;
            }
            let sec = &*(section_base.add(sec_offset) as *const SectionHeader);

            // Skip discardable sections
            if sec.characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0 {
                continue;
            }

            let sec_rva = sec.virtual_address as u64;
            let sec_vsize = if sec.virtual_size > 0 {
                sec.virtual_size as u64
            } else {
                sec.size_of_raw_data as u64
            };
            if sec_vsize == 0 {
                continue;
            }

            let sec_vaddr_start = load_base + sec_rva;
            let sec_page_start = page_align_down(sec_vaddr_start);
            let sec_page_end = page_align_up(sec_vaddr_start + sec_vsize);
            let flags = section_to_vspace_flags(sec.characteristics);

            let file_data_start = sec.pointer_to_raw_data as usize;
            let file_data_size = sec.size_of_raw_data as usize;

            let mut pv = sec_page_start;
            while pv < sec_page_end {
                // Calculate file data overlap for this page
                let page_rva = pv - load_base;
                let page_end_rva = page_rva + PE_PAGE_SIZE;

                // Determine what part of this page has file data
                let file_copy_start_rva = if page_rva > sec_rva {
                    page_rva
                } else {
                    sec_rva
                };
                let file_data_end_rva = sec_rva + file_data_size as u64;
                let file_copy_end_rva = if page_end_rva < file_data_end_rva {
                    page_end_rva
                } else {
                    file_data_end_rva
                };

                let (src_file_off, dst_page_off, copy_len) =
                    if file_copy_start_rva < file_copy_end_rva {
                        let rva_within_sec = file_copy_start_rva - sec_rva;
                        let src = file_data_start + rva_within_sec as usize;
                        let dst = (file_copy_start_rva - page_rva) as usize;
                        let len = (file_copy_end_rva - file_copy_start_rva) as usize;
                        (src, dst, len)
                    } else {
                        (0, 0, 0)
                    };

                let err = map_pe_page_raw(
                    data,
                    data_len,
                    pv,
                    src_file_off,
                    dst_page_off,
                    copy_len,
                    flags,
                    ctx,
                    &mut pages,
                    &mut page_count,
                );
                if err != 0 {
                    return err;
                }

                pv += PE_PAGE_SIZE;
            }
        }

        // --- Apply base relocations if the image was not loaded at its preferred base ---
        if delta != 0 {
            let err =
                pe_relocate(data, data_len, &info, delta, load_base, &pages[..page_count], ctx);
            if err != 0 {
                return err;
            }
        }

        (*result).entry = load_base + info.entry_point_rva as u64;
        (*result).base = load_base;
        (*result).image_end = image_end;
        PE_OK
    }
}

/// Map a single PE page: allocate a frame, zero it, copy file data at a
/// given file offset directly into the page at offset 0, then map into child.
///
/// # Safety
/// All pointer arguments must be valid.
unsafe fn map_pe_page(
    data: *const u8,
    data_len: usize,
    page_vaddr: u64,
    file_offset: usize,
    max_copy: usize,
    flags: u64,
    ctx: &mut ElfLoaderCtx,
    pages: &mut [PePageEntry; MAX_PE_PAGES],
    page_count: &mut usize,
) -> i32 {
    // Compute actual copy length (clamped to file bounds and page size)
    let copy_len = if file_offset < data_len {
        let avail = data_len - file_offset;
        let clamped = if avail < max_copy { avail } else { max_copy };
        if clamped > PE_PAGE_SIZE as usize {
            PE_PAGE_SIZE as usize
        } else {
            clamped
        }
    } else {
        0
    };

    unsafe {
        map_pe_page_raw(
            data,
            data_len,
            page_vaddr,
            file_offset,
            0, // dst offset within page = 0
            copy_len,
            flags,
            ctx,
            pages,
            page_count,
        )
    }
}

/// Map a single PE page with explicit src file offset, dst page offset, and copy length.
///
/// If a page at this vaddr already exists, merges permissions (W^X enforced).
/// Otherwise allocates a new frame, zeros it, copies file data, and maps into child.
///
/// # Safety
/// All pointer arguments must be valid.
unsafe fn map_pe_page_raw(
    data: *const u8,
    data_len: usize,
    page_vaddr: u64,
    src_file_off: usize,
    dst_page_off: usize,
    copy_len: usize,
    flags: u64,
    ctx: &mut ElfLoaderCtx,
    pages: &mut [PePageEntry; MAX_PE_PAGES],
    page_count: &mut usize,
) -> i32 {
    unsafe {
        // Check if this page was already mapped
        let mut existing_idx = *page_count;
        for j in 0..*page_count {
            if pages[j].vaddr == page_vaddr {
                existing_idx = j;
                break;
            }
        }

        if existing_idx < *page_count {
            // Page already exists — copy more data if needed
            if copy_len > 0 && src_file_off + copy_len <= data_len {
                let err = invoke::vspace_map(
                    ctx.self_vspace,
                    pages[existing_idx].frame_cap,
                    ctx.scratch_vaddr,
                    VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                );
                if err == 0 {
                    let scratch = ctx.scratch_vaddr as *mut u8;
                    for k in 0..copy_len {
                        core::ptr::write_volatile(
                            scratch.add(dst_page_off + k),
                            *data.add(src_file_off + k),
                        );
                    }
                    invoke::vspace_unmap(ctx.self_vspace, ctx.scratch_vaddr);
                }
            }

            // Merge permissions (W^X enforcement)
            let mut merged = pages[existing_idx].flags | flags;
            if (merged & VSPACE_FLAG_WRITABLE != 0) && (merged & VSPACE_FLAG_EXECUTABLE != 0) {
                merged &= !VSPACE_FLAG_EXECUTABLE;
            }
            if merged != pages[existing_idx].flags {
                invoke::vspace_unmap(ctx.child_vspace, page_vaddr);
                let err = invoke::vspace_map(ctx.child_vspace, pages[existing_idx].frame_cap, page_vaddr, merged);
                if err != 0 {
                    return PE_MAP_FAILED;
                }
                pages[existing_idx].flags = merged;
            }
            return PE_OK;
        }

        // New page
        if *page_count >= MAX_PE_PAGES {
            return PE_OUT_OF_MEMORY;
        }

        let frame_slot = next_frame_slot(ctx);
        if frame_slot == u64::MAX || frame_slot == 0 {
            return PE_OUT_OF_MEMORY;
        }

        // Retype frame if needed (untyped != 0 means internal allocation)
        if ctx.untyped != 0 {
            let err = try_retype_frame(ctx, frame_slot);
            if err != 0 {
                return PE_OUT_OF_MEMORY;
            }
        }

        // Map to scratch, zero, copy data
        let err = invoke::vspace_map(
            ctx.self_vspace,
            frame_slot,
            ctx.scratch_vaddr,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            return PE_MAP_FAILED;
        }

        let scratch = ctx.scratch_vaddr as *mut u8;
        // Zero entire page
        for k in 0..PE_PAGE_SIZE as usize {
            core::ptr::write_volatile(scratch.add(k), 0);
        }

        // Copy file data
        if copy_len > 0 && src_file_off + copy_len <= data_len {
            for k in 0..copy_len {
                core::ptr::write_volatile(
                    scratch.add(dst_page_off + k),
                    *data.add(src_file_off + k),
                );
            }
        }

        invoke::vspace_unmap(ctx.self_vspace, ctx.scratch_vaddr);

        // Map into child
        let err = invoke::vspace_map(ctx.child_vspace, frame_slot, page_vaddr, flags);
        if err != 0 {
            serial::serial_puts(b"[PE] map child failed\n");
            return PE_MAP_FAILED;
        }

        pages[*page_count] = PePageEntry {
            vaddr: page_vaddr,
            frame_cap: frame_slot,
            flags,
        };
        *page_count += 1;

        if let Some(record) = ctx.record_page {
            let rec_err = record(ctx.record_opaque, page_vaddr, frame_slot, flags);
            if rec_err != 0 {
                return PE_OUT_OF_MEMORY;
            }
        }

        PE_OK
    }
}

/// Get the next frame slot from the loader context.
fn next_frame_slot(ctx: &mut ElfLoaderCtx) -> Cap {
    if let Some(alloc) = ctx.alloc_frame_slot {
        unsafe { alloc(ctx.alloc_opaque) }
    } else {
        let slot = ctx.next_frame_slot;
        ctx.next_frame_slot += 1;
        slot
    }
}

/// Try to retype a frame from the context's untyped cap.
fn try_retype_frame(ctx: &mut ElfLoaderCtx, frame_slot: Cap) -> i32 {
    invoke::untyped_retype(ctx.untyped, OBJ_FRAME, 0, frame_slot)
}

/// Apply base relocations to a loaded PE image.
///
/// Reads the base relocation directory, iterates relocation blocks, and
/// patches IMAGE_REL_BASED_DIR64 entries by adding `delta` to each target.
///
/// # Safety
/// `data` must be valid for `data_len` bytes. `info` must be from a
/// successful `pe_validate`. `pages` must contain all mapped pages.
unsafe fn pe_relocate(
    data: *const u8,
    data_len: usize,
    info: &PeInfo,
    delta: u64,
    load_base: u64,
    pages: &[PePageEntry],
    ctx: &mut ElfLoaderCtx,
) -> i32 {
    unsafe {
        let reloc_dir = read_data_dir(data, data_len, info, IMAGE_DIRECTORY_ENTRY_BASERELOC);
        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
            // No relocations — image must be loaded at preferred base, or it's
            // position-independent without a reloc directory. Either way, return OK.
            return PE_OK;
        }

        // Convert reloc directory RVA to file offset by searching sections
        let reloc_file_off = match rva_to_file_offset(data, data_len, info, reloc_dir.virtual_address) {
            Some(off) => off,
            None => return PE_RELOC_FAILED,
        };

        let reloc_end = reloc_file_off + reloc_dir.size as usize;
        if reloc_end > data_len {
            return PE_RELOC_FAILED;
        }

        let mut pos = reloc_file_off;
        while pos + core::mem::size_of::<BaseRelocation>() <= reloc_end {
            let block = &*(data.add(pos) as *const BaseRelocation);
            if block.size_of_block == 0 {
                break;
            }
            if block.size_of_block < core::mem::size_of::<BaseRelocation>() as u32 {
                return PE_RELOC_FAILED;
            }

            let block_page_rva = block.virtual_address as u64;
            let entry_count = (block.size_of_block as usize
                - core::mem::size_of::<BaseRelocation>())
                / 2;
            let entries_ptr = data.add(pos + core::mem::size_of::<BaseRelocation>()) as *const u16;

            for i in 0..entry_count {
                let entry = *entries_ptr.add(i);
                let reloc_type = (entry >> 12) as u16;
                let offset = (entry & 0x0FFF) as u64;

                if reloc_type == IMAGE_REL_BASED_ABSOLUTE {
                    // Padding entry, skip
                    continue;
                }

                if reloc_type == IMAGE_REL_BASED_DIR64 {
                    let target_rva = block_page_rva + offset;
                    let target_vaddr = load_base + target_rva;
                    let target_page = page_align_down(target_vaddr);
                    let page_offset = (target_vaddr - target_page) as usize;

                    // Find the page in our mapped pages
                    let mut found = false;
                    for p in pages {
                        if p.vaddr == target_page {
                            let err = write_u64_to_page(ctx, p.frame_cap, page_offset, delta, true);
                            if err != 0 {
                                return PE_RELOC_FAILED;
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        serial::serial_puts(b"[PE] reloc target page not found\n");
                        return PE_RELOC_FAILED;
                    }
                } else {
                    // Unsupported relocation type — skip with warning
                    serial::serial_puts(b"[PE] unsupported reloc type\n");
                }
            }

            pos += block.size_of_block as usize;
            // Align to next 4-byte boundary
            pos = (pos + 3) & !3;
        }

        PE_OK
    }
}

/// Write a u64 delta-adjust into a frame page at the given offset.
///
/// If `additive` is true, reads the existing value and adds `value` to it.
/// Otherwise, writes `value` directly.
///
/// # Safety
/// `ctx` must have a valid scratch_vaddr and self_vspace.
unsafe fn write_u64_to_page(
    ctx: &mut ElfLoaderCtx,
    frame_cap: Cap,
    page_offset: usize,
    value: u64,
    additive: bool,
) -> i32 {
    let err = invoke::vspace_map(
        ctx.self_vspace,
        frame_cap,
        ctx.scratch_vaddr,
        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
    );
    if err != 0 {
        return err;
    }

    unsafe {
        let ptr = (ctx.scratch_vaddr as *mut u8).add(page_offset) as *mut u64;
        if additive {
            let old = core::ptr::read_volatile(ptr);
            core::ptr::write_volatile(ptr, old.wrapping_add(value));
        } else {
            core::ptr::write_volatile(ptr, value);
        }
    }

    invoke::vspace_unmap(ctx.self_vspace, ctx.scratch_vaddr);
    0
}

/// Convert an RVA to a file offset using the PE section table.
///
/// # Safety
/// `data` must be valid for `data_len` bytes.
unsafe fn rva_to_file_offset(
    data: *const u8,
    data_len: usize,
    info: &PeInfo,
    rva: u32,
) -> Option<usize> {
    unsafe {
        // Check if RVA is within headers (before first section)
        if rva < info.size_of_headers {
            return Some(rva as usize);
        }

        let section_base = data.add(info.section_headers_offset);
        for i in 0..info.number_of_sections as usize {
            let sec_offset = i * core::mem::size_of::<SectionHeader>();
            if info.section_headers_offset + sec_offset + core::mem::size_of::<SectionHeader>()
                > data_len
            {
                break;
            }
            let sec = &*(section_base.add(sec_offset) as *const SectionHeader);

            let sec_va = sec.virtual_address;
            let sec_vsize = if sec.virtual_size > 0 {
                sec.virtual_size
            } else {
                sec.size_of_raw_data
            };

            if rva >= sec_va && rva < sec_va + sec_vsize {
                let offset_within = rva - sec_va;
                if offset_within < sec.size_of_raw_data {
                    let file_off = sec.pointer_to_raw_data as usize + offset_within as usize;
                    if file_off < data_len {
                        return Some(file_off);
                    }
                }
                return None;
            }
        }
        None
    }
}

/// Parse the import directory of a PE file and extract DLL names.
///
/// # Safety
/// `data` must point to a valid PE file of at least `data_len` bytes.
/// `info` must have been populated by a successful `pe_validate` call.
pub unsafe fn pe_get_imports(
    data: *const u8,
    data_len: usize,
    info: &PeInfo,
) -> PeImports {
    let mut result = PeImports::new();

    unsafe {
        let import_dir = read_data_dir(data, data_len, info, IMAGE_DIRECTORY_ENTRY_IMPORT);
        if import_dir.virtual_address == 0 || import_dir.size == 0 {
            return result;
        }

        let import_file_off = match rva_to_file_offset(data, data_len, info, import_dir.virtual_address) {
            Some(off) => off,
            None => return result,
        };

        let mut pos = import_file_off;
        loop {
            if pos + core::mem::size_of::<ImportDescriptor>() > data_len {
                break;
            }

            let desc = &*(data.add(pos) as *const ImportDescriptor);
            if desc.is_null() {
                break;
            }

            if result.count >= MAX_PE_IMPORTS {
                break;
            }

            // Read DLL name
            if let Some(name_off) = rva_to_file_offset(data, data_len, info, desc.name_rva) {
                let name_ptr = data.add(name_off);
                let mut len = 0usize;
                while name_off + len < data_len
                    && *name_ptr.add(len) != 0
                    && len < MAX_PE_IMPORT_NAME
                {
                    len += 1;
                }
                if len > 0 {
                    for j in 0..len {
                        result.names[result.count][j] = *name_ptr.add(j);
                    }
                    result.name_lens[result.count] = len;
                    result.count += 1;
                }
            }

            pos += core::mem::size_of::<ImportDescriptor>();
        }
    }

    result
}

/// Resolve imports for a loaded PE image by writing function addresses
/// into the Import Address Table (IAT).
///
/// For each imported DLL, calls `resolve_fn` with the DLL name and function
/// name (or ordinal). The callback must return the resolved address, or 0
/// if the symbol cannot be found.
///
/// # Safety
/// `data` must be valid for `data_len` bytes. `info` must be from a
/// successful `pe_validate`. `pages` must contain all mapped pages.
/// `resolve_fn` must be a valid function pointer.
pub unsafe fn pe_resolve_imports(
    data: *const u8,
    data_len: usize,
    info: &PeInfo,
    load_base: u64,
    pages: &[PePageEntry],
    ctx: &mut ElfLoaderCtx,
    resolve_fn: unsafe extern "C" fn(
        dll_name: *const u8,
        dll_name_len: usize,
        func_name: *const u8,
        func_name_len: usize,
        ordinal: u16,
        opaque: *mut u8,
    ) -> u64,
    resolve_opaque: *mut u8,
) -> i32 {
    unsafe {
        let import_dir = read_data_dir(data, data_len, info, IMAGE_DIRECTORY_ENTRY_IMPORT);
        if import_dir.virtual_address == 0 || import_dir.size == 0 {
            return PE_OK; // No imports
        }

        let import_file_off = match rva_to_file_offset(data, data_len, info, import_dir.virtual_address) {
            Some(off) => off,
            None => return PE_BAD_IMPORT,
        };

        let mut pos = import_file_off;
        loop {
            if pos + core::mem::size_of::<ImportDescriptor>() > data_len {
                break;
            }

            let desc = &*(data.add(pos) as *const ImportDescriptor);
            if desc.is_null() {
                break;
            }

            // Read DLL name
            let name_off = match rva_to_file_offset(data, data_len, info, desc.name_rva) {
                Some(off) => off,
                None => {
                    pos += core::mem::size_of::<ImportDescriptor>();
                    continue;
                }
            };
            let dll_name_ptr = data.add(name_off);
            let mut dll_name_len = 0usize;
            while name_off + dll_name_len < data_len && *dll_name_ptr.add(dll_name_len) != 0 {
                dll_name_len += 1;
            }

            // Walk the ILT (OriginalFirstThunk) and IAT (FirstThunk) in parallel.
            // ILT tells us what to import; IAT is where we write the resolved address.
            let ilt_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk
            } else {
                desc.first_thunk
            };
            let iat_rva = desc.first_thunk;

            let ilt_file_off = match rva_to_file_offset(data, data_len, info, ilt_rva) {
                Some(off) => off,
                None => {
                    pos += core::mem::size_of::<ImportDescriptor>();
                    continue;
                }
            };

            let mut entry_idx: usize = 0;
            loop {
                let ilt_entry_off = ilt_file_off + entry_idx * 8;
                if ilt_entry_off + 8 > data_len {
                    break;
                }

                let ilt_entry = core::ptr::read_unaligned(data.add(ilt_entry_off) as *const u64);
                if ilt_entry == 0 {
                    break;
                }

                let (func_name_ptr, func_name_len, ordinal) =
                    if ilt_entry & (1u64 << 63) != 0 {
                        // Import by ordinal
                        let ord = (ilt_entry & 0xFFFF) as u16;
                        (core::ptr::null(), 0usize, ord)
                    } else {
                        // Import by name — hint/name table entry
                        let hint_rva = (ilt_entry & 0x7FFF_FFFF) as u32;
                        match rva_to_file_offset(data, data_len, info, hint_rva) {
                            Some(hint_off) => {
                                // Skip 2-byte hint (ordinal hint)
                                let name_start = hint_off + 2;
                                if name_start < data_len {
                                    let fnp = data.add(name_start);
                                    let mut fnl = 0usize;
                                    while name_start + fnl < data_len && *fnp.add(fnl) != 0 {
                                        fnl += 1;
                                    }
                                    (fnp, fnl, 0u16)
                                } else {
                                    (core::ptr::null(), 0usize, 0u16)
                                }
                            }
                            None => (core::ptr::null(), 0usize, 0u16),
                        }
                    };

                // Resolve the symbol
                let resolved_addr = resolve_fn(
                    dll_name_ptr,
                    dll_name_len,
                    func_name_ptr,
                    func_name_len,
                    ordinal,
                    resolve_opaque,
                );

                // Write resolved address into the IAT
                let iat_entry_rva = iat_rva as u64 + (entry_idx as u64) * 8;
                let iat_vaddr = load_base + iat_entry_rva;
                let iat_page = page_align_down(iat_vaddr);
                let iat_page_off = (iat_vaddr - iat_page) as usize;

                let mut written = false;
                for p in pages.iter() {
                    if p.vaddr == iat_page {
                        let err = write_u64_to_page(ctx, p.frame_cap, iat_page_off, resolved_addr, false);
                        if err != 0 {
                            return PE_BAD_IMPORT;
                        }
                        written = true;
                        break;
                    }
                }
                if !written {
                    serial::serial_puts(b"[PE] IAT page not found\n");
                    return PE_BAD_IMPORT;
                }

                entry_idx += 1;
            }

            pos += core::mem::size_of::<ImportDescriptor>();
        }

        PE_OK
    }
}
