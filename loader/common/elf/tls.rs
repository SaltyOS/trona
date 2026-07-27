//! SPDX-License-Identifier: GPL-2.0-only
//! ELF TLS (Thread-Local Storage) layout types
//!
//! Module-ID space: static modules registered at process startup occupy
//! `1..=TLS_MAX_MODULES` (set by [`tls_alloc_module`]). Modules registered at
//! runtime through [`register_dynamic_module`] live above
//! [`DYNAMIC_TLS_MODULE_BASE`] and are tracked by the rtld in a separate
//! per-thread DTV (dynamic thread vector). `__tls_get_addr` decides the bin
//! by comparing `module_id < DYNAMIC_TLS_MODULE_BASE`.

/// Maximum number of TLS modules tracked by the RTLD.
pub const TLS_MAX_MODULES: usize = 16;

/// First module ID reserved for runtime-loaded (dlopen) TLS modules. Static
/// PT_TLS segments seen at startup never reach this value because
/// [`tls_alloc_module`] caps `mod_id` at `TLS_MAX_MODULES`.
pub const DYNAMIC_TLS_MODULE_BASE: u32 = (TLS_MAX_MODULES as u32) + 1;

/// Discriminator for a TLS module ID.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlsModuleKind {
    /// Module ID was issued by [`tls_alloc_module`] at startup.
    Static,
    /// Module ID was issued by [`register_dynamic_module`] for a dlopen-loaded
    /// object.
    Dynamic,
}

/// Classify a module ID by ID space.
#[inline]
pub const fn tls_module_kind(mod_id: u32) -> TlsModuleKind {
    if mod_id >= DYNAMIC_TLS_MODULE_BASE {
        TlsModuleKind::Dynamic
    } else {
        TlsModuleKind::Static
    }
}

/// Describes one shared object's static TLS segment (registered at startup).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct TlsModule {
    /// Load base address of the module.
    pub base: usize,
    /// File size of the PT_TLS segment (initialized data).
    pub filesz: usize,
    /// Memory size of the PT_TLS segment (filesz + bss).
    pub memsz: usize,
    /// Alignment requirement from PT_TLS.
    pub align: usize,
    /// Offset of this module's block within the static TLS area.
    pub offset: usize,
    /// 1-based module ID (0 = unused slot).
    pub mod_id: usize,
}

/// Describes one runtime-registered (dlopen-loaded) TLS module.
///
/// Unlike `TlsModule`, dynamic modules have no fixed offset within the static
/// TLS region. Storage is allocated lazily, per thread, on the first
/// `__tls_get_addr` call referencing the module. `template` points to the
/// PT_TLS image so the rtld can `memcpy` the initialized portion.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DynamicTlsModule {
    /// Pointer to the PT_TLS template image (initialized bytes).
    pub template: *const u8,
    /// Number of initialized bytes to `memcpy` from `template`.
    pub filesz: usize,
    /// Total module size in bytes (`memsz - filesz` is zero-init tail).
    pub memsz: usize,
    /// Required alignment.
    pub align: usize,
    /// Module ID assigned by the rtld; lives in the dynamic ID space.
    pub mod_id: u32,
}

unsafe impl Send for DynamicTlsModule {}
unsafe impl Sync for DynamicTlsModule {}

impl DynamicTlsModule {
    pub const fn empty() -> Self {
        DynamicTlsModule {
            template: core::ptr::null(),
            filesz: 0,
            memsz: 0,
            align: 1,
            mod_id: 0,
        }
    }
}

/// Build a [`DynamicTlsModule`] descriptor for a runtime-loaded object. The
/// caller (the rtld) owns the registry that maps `mod_id` to descriptor.
#[inline]
pub fn register_dynamic_module(
    template: *const u8,
    filesz: usize,
    memsz: usize,
    align: usize,
    mod_id: u32,
) -> DynamicTlsModule {
    DynamicTlsModule {
        template,
        filesz,
        memsz,
        align: if align == 0 { 1 } else { align },
        mod_id,
    }
}

/// Aggregate TLS layout for all loaded modules.
#[derive(Clone, Copy, Default)]
pub struct TlsLayout {
    /// Total size of the static TLS region.
    pub size: usize,
    /// Overall alignment of the TLS region.
    pub align: usize,
    /// Number of allocated module slots.
    pub count: usize,
}

/// Allocates a TLS module slot and updates the aggregate layout.
///
/// Returns the 1-based module ID, or `None` if `TLS_MAX_MODULES` is
/// exhausted.
pub fn tls_alloc_module(
    layout: &mut TlsLayout,
    modules: &mut [TlsModule; TLS_MAX_MODULES],
    memsz: usize,
    filesz: usize,
    align: usize,
    base: usize,
) -> Option<usize> {
    if layout.count >= TLS_MAX_MODULES {
        return None;
    }

    let align = if align == 0 { 1 } else { align };
    let mod_id = layout.count + 1;

    // variant II (x86_64): TLS grows downward from TP
    // variant I  (aarch64): TLS grows upward from TP+16
    // We compute offsets at setup time; architecture entry code
    // adjusts the TP accordingly.
    let size = align_up(layout.size + memsz, align);

    let slot = &mut modules[layout.count];
    *slot = TlsModule {
        base,
        filesz,
        memsz,
        align,
        offset: size - memsz,
        mod_id,
    };

    layout.size = size;
    if align > layout.align {
        layout.align = align;
    }
    layout.count += 1;

    Some(mod_id)
}

#[inline]
const fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}
