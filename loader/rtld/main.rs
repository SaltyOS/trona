//! SPDX-License-Identifier: GPL-2.0-only
//! Unified RTLD entry dispatch.

use crate::rtld::io;
use crate::rtld::serial;
use trona_kernel::core_types::{SALTYOS_IMAGE_KIND_ELF, SALTYOS_IMAGE_KIND_PE};

#[unsafe(no_mangle)]
pub static mut rtld_startup_image_kind: u64 = 0;

#[unsafe(no_mangle)]
pub static rtld_pe_image_kind: u64 = SALTYOS_IMAGE_KIND_PE as u64;

/// RTLD C entry point, called from start.S after self-relocation.
///
/// # Safety
/// `sp` must point to the initial stack (argc/argv/envp/auxv layout).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtld_main(sp: *const usize) -> usize {
    let stack = unsafe { io::parse_stack(sp) };
    let auxv = unsafe { io::parse_auxv(stack.auxv) };

    unsafe { *(&raw mut rtld_startup_image_kind) = auxv.main_image.kind as u64 };

    match auxv.main_image.kind {
        SALTYOS_IMAGE_KIND_PE => unsafe { crate::rtld::pe::main::run(sp) },
        SALTYOS_IMAGE_KIND_ELF => unsafe { crate::rtld::elf::main::run(sp) },
        _ if auxv.at_phdr != 0 && auxv.at_phnum != 0 => unsafe { crate::rtld::elf::main::run(sp) },
        _ => serial::fatal("unsupported startup image kind"),
    }
}
