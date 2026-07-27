//! SPDX-License-Identifier: GPL-2.0-only
//! PE base relocation processing

use super::types::*;

/// Applies all base relocations to a PE image.
///
/// `image_base` is the actual load address. `preferred_base` is the
/// `OptionalHeader64::image_base` value. The delta is applied to every
/// fixup entry.
///
/// # Safety
/// `reloc_dir` must describe a valid base relocation table within the
/// mapped image at `image_base`.
pub unsafe fn apply_base_relocations(
    image_base: usize,
    preferred_base: u64,
    reloc_rva: u32,
    reloc_size: u32,
) {
    let delta = image_base as i64 - preferred_base as i64;
    if delta == 0 {
        return;
    }

    let mut offset = 0u32;
    while offset < reloc_size {
        let block = unsafe {
            &*((image_base + reloc_rva as usize + offset as usize) as *const BaseRelocation)
        };
        if block.size_of_block == 0 {
            break;
        }

        let entry_count =
            (block.size_of_block as usize - core::mem::size_of::<BaseRelocation>()) / 2;
        let entries = unsafe {
            core::slice::from_raw_parts(
                (block as *const BaseRelocation).add(1) as *const u16,
                entry_count,
            )
        };

        for &entry in entries {
            let typ = entry >> 12;
            let off = (entry & 0x0FFF) as u32;
            let target = image_base + block.virtual_address as usize + off as usize;

            match typ {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 => unsafe {
                    let p = target as *mut u64;
                    p.write(p.read().wrapping_add(delta as u64));
                },
                IMAGE_REL_BASED_HIGHLOW => unsafe {
                    let p = target as *mut u32;
                    p.write(p.read().wrapping_add(delta as u32));
                },
                IMAGE_REL_BASED_HIGH => unsafe {
                    let p = target as *mut u16;
                    p.write(p.read().wrapping_add((delta >> 16) as u16));
                },
                IMAGE_REL_BASED_LOW => unsafe {
                    let p = target as *mut u16;
                    p.write(p.read().wrapping_add(delta as u16));
                },
                _ => {}
            }
        }

        offset += block.size_of_block;
    }
}
