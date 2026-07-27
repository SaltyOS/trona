//! SPDX-License-Identifier: GPL-2.0-only
//! PE import table resolution

use super::types::*;

/// Walks the import directory and yields each import descriptor.
///
/// # Safety
/// `image_base` must be the mapped PE image base and `import_rva`/`import_size`
/// must describe a valid import directory within it.
pub unsafe fn iter_import_descriptors(
    image_base: usize,
    import_rva: u32,
    import_size: u32,
) -> ImportIter {
    let count = import_size as usize / core::mem::size_of::<ImportDescriptor>();
    ImportIter {
        base: image_base,
        ptr: (image_base + import_rva as usize) as *const ImportDescriptor,
        remaining: count,
    }
}

/// Iterator over PE import descriptors.
pub struct ImportIter {
    base: usize,
    ptr: *const ImportDescriptor,
    remaining: usize,
}

impl Iterator for ImportIter {
    type Item = ImportEntry;

    fn next(&mut self) -> Option<ImportEntry> {
        while self.remaining > 0 {
            let desc = unsafe { &*self.ptr };
            self.ptr = unsafe { self.ptr.add(1) };
            self.remaining -= 1;

            // Null descriptor marks end of import table
            if desc.name == 0 && desc.first_thunk == 0 {
                return None;
            }

            return Some(ImportEntry {
                base: self.base,
                desc,
            });
        }
        None
    }
}

/// A single import directory entry with helpers.
pub struct ImportEntry {
    base: usize,
    pub desc: &'static ImportDescriptor,
}

impl ImportEntry {
    /// Returns the DLL name as a byte slice (null-terminated in image).
    ///
    /// # Safety
    /// The image must still be mapped.
    pub unsafe fn dll_name(&self) -> &'static [u8] {
        let ptr = (self.base + self.desc.name as usize) as *const u8;
        let mut len = 0;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }

    /// Returns the ILT (Import Lookup Table) entries, if present.
    /// Falls back to the IAT if `original_first_thunk` is zero.
    pub fn lookup_table_rva(&self) -> u32 {
        if self.desc.original_first_thunk != 0 {
            self.desc.original_first_thunk
        } else {
            self.desc.first_thunk
        }
    }

    /// Returns a pointer to the IAT (Import Address Table) for patching.
    pub fn iat_ptr(&self) -> *mut u64 {
        (self.base + self.desc.first_thunk as usize) as *mut u64
    }
}

/// Checks if an ILT entry is an ordinal import (bit 63 set).
#[inline]
pub const fn is_ordinal(entry: u64) -> bool {
    entry & (1u64 << 63) != 0
}

/// Extracts the ordinal number from an ordinal ILT entry.
#[inline]
pub const fn ordinal(entry: u64) -> u16 {
    entry as u16
}

/// Extracts the Hint/Name RVA from a named ILT entry.
#[inline]
pub const fn hint_name_rva(entry: u64) -> u32 {
    entry as u32
}

/// Reads the hint value from a Hint/Name table entry.
///
/// # Safety
/// `image_base + rva` must point to a valid hint/name entry.
pub unsafe fn hint_name_hint(image_base: usize, rva: u32) -> u16 {
    unsafe { *((image_base + rva as usize) as *const u16) }
}

/// Reads the name from a Hint/Name table entry.
///
/// # Safety
/// `image_base + rva` must point to a valid hint/name entry.
pub unsafe fn hint_name_name(image_base: usize, rva: u32) -> &'static [u8] {
    let ptr = (image_base + rva as usize + 2) as *const u8; // skip hint u16
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    unsafe { core::slice::from_raw_parts(ptr, len) }
}
