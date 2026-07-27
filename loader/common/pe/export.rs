//! SPDX-License-Identifier: GPL-2.0-only
//! PE export resolution over already-mapped module images.

use super::header;
use super::types::*;

#[derive(Clone, Copy)]
pub struct PeModuleImage<'a> {
    pub name: &'a [u8],
    pub base: usize,
    pub size: usize,
}

#[derive(Clone, Copy)]
pub enum ImportSymbol<'a> {
    Name(&'a [u8]),
    Ordinal(u16),
}

pub fn find_module<'a, 'b>(
    modules: &'a [PeModuleImage<'b>],
    requested: &[u8],
) -> Option<&'a PeModuleImage<'b>> {
    let requested = canonical_module_name(requested);
    for module in modules {
        if module.base == 0 || module.size == 0 {
            continue;
        }
        if module_name_eq(canonical_module_name(module.name), requested) {
            return Some(module);
        }
    }
    None
}

pub fn resolve_import<'a>(
    modules: &[PeModuleImage<'a>],
    module_name: &[u8],
    symbol: ImportSymbol<'_>,
) -> Option<usize> {
    let module = find_module(modules, module_name)?;
    resolve_export_with_depth(modules, module, symbol, 0)
}

pub fn resolve_export<'a>(
    modules: &[PeModuleImage<'a>],
    module: &PeModuleImage<'a>,
    symbol: ImportSymbol<'_>,
) -> Option<usize> {
    resolve_export_with_depth(modules, module, symbol, 0)
}

fn resolve_export_with_depth<'a>(
    modules: &[PeModuleImage<'a>],
    module: &PeModuleImage<'a>,
    symbol: ImportSymbol<'_>,
    depth: usize,
) -> Option<usize> {
    if depth >= 8 {
        return None;
    }

    let base = module.base as *const u8;
    let pe = unsafe { header::validate(base, module.size).ok()? };
    let export_dirent = unsafe { pe.data_directory(base, IMAGE_DIRECTORY_ENTRY_EXPORT)? };
    let export_dir = unsafe {
        &*((module.base + export_dirent.virtual_address as usize) as *const ExportDirectory)
    };

    let func_index = match symbol {
        ImportSymbol::Name(name) => resolve_name_index(module, export_dir, name)?,
        ImportSymbol::Ordinal(ordinal) => {
            if (ordinal as u32) < export_dir.base {
                return None;
            }
            let idx = ordinal as u32 - export_dir.base;
            if idx >= export_dir.number_of_functions {
                return None;
            }
            idx
        }
    };

    let funcs = (module.base + export_dir.address_of_functions as usize) as *const u32;
    let func_rva = unsafe { *funcs.add(func_index as usize) };
    if func_rva == 0 {
        return None;
    }
    let export_lo = export_dirent.virtual_address;
    let export_hi = export_lo.checked_add(export_dirent.size)?;

    if func_rva >= export_lo && func_rva < export_hi {
        let forwarder = unsafe { c_string((module.base + func_rva as usize) as *const u8) };
        let (target_module, target_symbol) = parse_forwarder(forwarder)?;
        let target = find_module(modules, target_module)?;
        return resolve_export_with_depth(modules, target, target_symbol, depth + 1);
    }

    Some(module.base + func_rva as usize)
}

fn resolve_name_index(
    module: &PeModuleImage<'_>,
    export_dir: &ExportDirectory,
    requested: &[u8],
) -> Option<u32> {
    let names = (module.base + export_dir.address_of_names as usize) as *const u32;
    let ordinals = (module.base + export_dir.address_of_name_ordinals as usize) as *const u16;

    let mut i = 0u32;
    while i < export_dir.number_of_names {
        let name_rva = unsafe { *names.add(i as usize) };
        let name = unsafe { c_string((module.base + name_rva as usize) as *const u8) };
        if name == requested {
            let ordinal_index = unsafe { *ordinals.add(i as usize) } as u32;
            if ordinal_index < export_dir.number_of_functions {
                return Some(ordinal_index);
            }
            return None;
        }
        i += 1;
    }

    None
}

fn parse_forwarder(forwarder: &[u8]) -> Option<(&[u8], ImportSymbol<'_>)> {
    let mut dot = None;
    let mut i = 0usize;
    while i < forwarder.len() {
        if forwarder[i] == b'.' {
            dot = Some(i);
        }
        i += 1;
    }
    let dot = dot?;
    let module = &forwarder[..dot];
    let symbol = &forwarder[dot + 1..];
    if symbol.is_empty() {
        return None;
    }
    if symbol[0] == b'#' {
        let mut ordinal = 0u16;
        let mut j = 1usize;
        while j < symbol.len() {
            let ch = symbol[j];
            if !ch.is_ascii_digit() {
                return None;
            }
            ordinal = ordinal.checked_mul(10)?.checked_add((ch - b'0') as u16)?;
            j += 1;
        }
        Some((module, ImportSymbol::Ordinal(ordinal)))
    } else {
        Some((module, ImportSymbol::Name(symbol)))
    }
}

unsafe fn c_string(ptr: *const u8) -> &'static [u8] {
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

fn canonical_module_name(name: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut i = 0usize;
    while i < name.len() {
        if name[i] == b'/' || name[i] == b'\\' {
            start = i + 1;
        }
        i += 1;
    }
    let mut out = &name[start..];
    if out.len() >= 4 && ascii_eq_ignore_case(&out[out.len() - 4..], b".dll") {
        out = &out[..out.len() - 4];
    }
    out
}

fn module_name_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    ascii_eq_ignore_case(a, b)
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0usize;
    while i < a.len() {
        if fold_ascii(a[i]) != fold_ascii(b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

const fn fold_ascii(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { b + 32 } else { b }
}
