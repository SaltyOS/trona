//! SPDX-License-Identifier: GPL-2.0-only
//! RTLD I/O helpers (auxv parsing, stack walking)

use crate::common::elf::types::*;
use trona_kernel::core_types::{
    SALTYOS_STARTUP_MAX_MAPPED_IMAGES, SaltyOSCapTableV1, SaltyOSCspaceLayoutV1,
    SaltyOSImageInfoV1, SaltyOSMappedImageV1, SaltyOSStartupLayoutV1,
};

/// Parsed auxiliary vector values relevant to the RTLD.
#[derive(Clone, Copy)]
pub struct AuxvInfo {
    pub at_phdr: usize,
    pub at_phent: usize,
    pub at_phnum: usize,
    pub at_pagesz: usize,
    pub at_base: usize,
    pub at_entry: usize,
    pub startup: usize,
    pub ipc_buffer_vaddr: usize,
    pub scratch_vaddr: usize,
    pub cspace_layout_ptr: usize,
    pub cap_table_ptr: usize,
    pub dso_window_base: usize,
    pub dso_window_size: usize,
    pub main_image: SaltyOSImageInfoV1,
    /// Raw auxv pointer (for passing to libtrona's runtime init).
    pub raw_auxv: *const Elf64Auxv,
}

impl AuxvInfo {
    const fn zeroed() -> Self {
        Self {
            at_phdr: 0,
            at_phent: 0,
            at_phnum: 0,
            at_pagesz: 0,
            at_base: 0,
            at_entry: 0,
            startup: 0,
            ipc_buffer_vaddr: 0,
            scratch_vaddr: 0,
            cspace_layout_ptr: 0,
            cap_table_ptr: 0,
            dso_window_base: 0,
            dso_window_size: 0,
            main_image: SaltyOSImageInfoV1::zeroed(),
            raw_auxv: core::ptr::null(),
        }
    }

    pub fn startup_block(&self) -> Option<&'static SaltyOSStartupLayoutV1> {
        if self.startup == 0 {
            return None;
        }
        let startup = unsafe { &*(self.startup as *const SaltyOSStartupLayoutV1) };
        if startup.is_valid() {
            Some(startup)
        } else {
            None
        }
    }

    pub fn cspace_layout(&self) -> Option<&'static SaltyOSCspaceLayoutV1> {
        if self.cspace_layout_ptr == 0 {
            return None;
        }
        let layout = unsafe { &*(self.cspace_layout_ptr as *const SaltyOSCspaceLayoutV1) };
        if layout.version == SaltyOSCspaceLayoutV1::VERSION {
            Some(layout)
        } else {
            None
        }
    }

    pub fn cap_slot(&self, role_id: u32) -> u32 {
        if self.cap_table_ptr == 0 {
            return 0;
        }
        match trona_runtime::spawn::cap_table::lookup(
            self.cap_table_ptr as *const SaltyOSCapTableV1,
            role_id,
        ) {
            Some(entry) => entry.slot,
            None => 0,
        }
    }

    pub fn mapped_images(&self) -> &'static [SaltyOSMappedImageV1] {
        let Some(startup) = self.startup_block() else {
            return &[];
        };
        let count = core::cmp::min(
            startup.mapped_image_count as usize,
            SALTYOS_STARTUP_MAX_MAPPED_IMAGES,
        );
        &startup.mapped_images[..count]
    }
}

/// Parses the auxiliary vector starting at `auxv`.
///
/// # Safety
/// `auxv` must point to a valid AT_NULL-terminated auxv array.
pub unsafe fn parse_auxv(auxv: *const Elf64Auxv) -> AuxvInfo {
    let mut info = AuxvInfo::zeroed();
    info.raw_auxv = auxv;
    let mut p = auxv;

    loop {
        let entry = unsafe { &*p };
        match entry.a_type {
            AT_NULL => break,
            AT_PHDR => info.at_phdr = entry.a_val as usize,
            AT_PHENT => info.at_phent = entry.a_val as usize,
            AT_PHNUM => info.at_phnum = entry.a_val as usize,
            AT_PAGESZ => info.at_pagesz = entry.a_val as usize,
            AT_BASE => info.at_base = entry.a_val as usize,
            AT_ENTRY => info.at_entry = entry.a_val as usize,
            AT_SALTYOS_STARTUP => info.startup = entry.a_val as usize,
            _ => {}
        }
        p = unsafe { p.add(1) };
    }

    if let Some(startup) = info.startup_block() {
        info.ipc_buffer_vaddr = startup.ipc_buffer_vaddr as usize;
        info.scratch_vaddr = startup.scratch_vaddr as usize;
        info.cspace_layout_ptr = startup.cspace_layout_ptr as usize;
        info.cap_table_ptr = startup.cap_table_ptr as usize;
        info.dso_window_base = startup.dso_window_base as usize;
        info.dso_window_size = startup.dso_window_size as usize;
        info.main_image = startup.main_image;
    }

    info
}

/// Walks the initial stack to find argc, argv, envp, and auxv.
///
/// Stack layout: [argc] [argv0..argvN] [NULL] [env0..envN] [NULL] [auxv...]
///
/// # Safety
/// `sp` must point to the top of a valid SysV-style initial stack.
pub unsafe fn parse_stack(sp: *const usize) -> StackInfo {
    let argc = unsafe { *sp } as usize;
    let argv = unsafe { sp.add(1) } as *const *const u8;

    // Skip past argv + null terminator
    let mut p = unsafe { sp.add(1 + argc + 1) };

    // Skip envp
    let envp = p as *const *const u8;
    while unsafe { *p } != 0 {
        p = unsafe { p.add(1) };
    }
    p = unsafe { p.add(1) }; // skip null terminator

    let auxv = p as *const Elf64Auxv;

    StackInfo {
        argc,
        argv,
        envp,
        auxv,
    }
}

/// Parsed initial stack pointers.
pub struct StackInfo {
    pub argc: usize,
    pub argv: *const *const u8,
    pub envp: *const *const u8,
    pub auxv: *const Elf64Auxv,
}
