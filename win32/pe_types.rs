// SPDX-License-Identifier: GPL-2.0-only
//
//! PE/COFF on-disk types — Win32 binary parsing.
//!
//! Layout-stable `#[repr(C)]` mirrors of the Microsoft PE/COFF spec
//! used by the win32 personality (rtld PE loader, kernel32.dll
//! shim). Field names follow the Microsoft PE Format reference.

/// DOS header (`IMAGE_DOS_HEADER`). The first 64 bytes of any PE
/// file. Only `e_magic` (MZ) and `e_lfanew` (PE header offset) are
/// used.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    /// File offset to the PE signature ("PE\0\0").
    pub e_lfanew: u32,
}

/// COFF file header (`IMAGE_FILE_HEADER`). Immediately follows the PE
/// signature.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Data directory entry (`IMAGE_DATA_DIRECTORY`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub const fn zeroed() -> Self {
        DataDirectory {
            virtual_address: 0,
            size: 0,
        }
    }
}

/// PE32+ optional header (`IMAGE_OPTIONAL_HEADER64`). Only the PE32+
/// (64-bit) format is supported.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    // Data directories follow inline (up to 16 entries) and are read
    // separately via pointer arithmetic.
}

/// Section header (`IMAGE_SECTION_HEADER`). 40 bytes each.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// Import directory entry (`IMAGE_IMPORT_DESCRIPTOR`). A
/// null-terminated array of these describes DLL imports.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImportDescriptor {
    /// RVA of the Import Lookup Table (ILT) / OriginalFirstThunk.
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    /// RVA of the DLL name string.
    pub name_rva: u32,
    /// RVA of the Import Address Table (IAT) / FirstThunk.
    pub first_thunk: u32,
}

impl ImportDescriptor {
    /// Check if this is the null terminator entry.
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0 && self.name_rva == 0 && self.first_thunk == 0
    }
}

/// Base relocation block header (`IMAGE_BASE_RELOCATION`). Each
/// block covers relocations within a single page; followed by a
/// variable number of `u16` type+offset entries.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BaseRelocation {
    /// Page RVA that this block's entries apply to.
    pub virtual_address: u32,
    /// Total size of this block including the header and all entries.
    pub size_of_block: u32,
}

/// Result of loading a PE binary: entry point, load base address,
/// and the end of the loaded image (image break).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PeLoadResult {
    pub entry: u64,
    pub base: u64,
    pub image_end: u64,
}

impl PeLoadResult {
    pub const fn zeroed() -> Self {
        PeLoadResult {
            entry: 0,
            base: 0,
            image_end: 0,
        }
    }
}
