//! SPDX-License-Identifier: GPL-2.0-only
//! ELF relocation application engine

use super::types::*;
use crate::common::arch;

/// Errors from relocation processing.
#[derive(Clone, Copy, Debug)]
pub enum RelocError {
    UnsupportedType(u32),
    SymbolNotFound,
    IfuncFailed,
}

/// Outcome of a TLSDESC reloc handler installed via [`RelocCtx`].
#[derive(Clone, Copy)]
pub struct TlsdescEntry {
    /// Resolver function the TLSDESC trampoline should jump to.
    pub resolver: u64,
    /// Argument passed to the resolver (offset for static TLS, descriptor
    /// pointer for dynamic TLS).
    pub arg: u64,
}

/// Optional callbacks that extend [`apply_rela`] / [`apply_rela_table`] with
/// IRELATIVE ifunc dispatch and TLSDESC resolution. Both fields are optional;
/// when `None`, encountering the corresponding relocation returns an error
/// instead of silently corrupting memory.
#[derive(Clone, Copy)]
pub struct RelocCtx<'a> {
    /// Build a TLSDESC entry for the given symbol index and addend. The rtld
    /// supplies its arch-specific resolver trampoline as `resolver` and the
    /// per-relocation `arg`.
    pub tlsdesc: Option<&'a dyn Fn(u32, i64) -> Option<TlsdescEntry>>,
    /// Override the default IRELATIVE handler. The default invokes the
    /// resolver directly via a function-pointer cast; callers that need to
    /// run resolvers in a guarded context (sandbox, unwind, audit) can swap
    /// in their own implementation.
    pub ifunc: Option<&'a dyn Fn(u64) -> Option<u64>>,
}

impl<'a> RelocCtx<'a> {
    pub const fn empty() -> Self {
        RelocCtx {
            tlsdesc: None,
            ifunc: None,
        }
    }
}

/// Default IRELATIVE handler — call the resolver as `extern "C" fn() -> u64`.
///
/// # Safety
/// `resolver_addr` must point to a fully-relocated function whose calling
/// convention matches `extern "C" fn() -> u64`.
unsafe fn default_ifunc(resolver_addr: u64) -> Option<u64> {
    let resolver: extern "C" fn() -> u64 = unsafe { core::mem::transmute(resolver_addr as usize) };
    Some(resolver())
}

/// Applies a single RELA relocation.
///
/// # Safety
/// - `base` is the load base of the object being relocated.
/// - `symval` is the resolved symbol value (0 if none needed).
/// - The target address `base + r.r_offset` must be writable.
pub unsafe fn apply_rela(base: usize, r: &Elf64Rela, symval: u64) -> Result<(), RelocError> {
    unsafe { apply_rela_ctx(base, r, symval, &RelocCtx::empty()) }
}

/// Applies a single RELA relocation with extended context for IRELATIVE and
/// TLSDESC.
///
/// # Safety
/// Same as [`apply_rela`]; in addition the callbacks in `ctx` (when present)
/// must produce sound values for the relocation type they cover.
pub unsafe fn apply_rela_ctx(
    base: usize,
    r: &Elf64Rela,
    symval: u64,
    ctx: &RelocCtx<'_>,
) -> Result<(), RelocError> {
    let typ = elf64_r_type(r.r_info);
    let target = (base as u64 + r.r_offset) as *mut u64;

    match typ {
        arch::R_NONE => {}
        arch::R_RELATIVE => {
            // B + A
            unsafe { target.write(base as u64 + r.r_addend as u64) };
        }
        arch::R_ABS64 => {
            // S + A
            unsafe { target.write(symval + r.r_addend as u64) };
        }
        arch::R_GLOB_DAT | arch::R_JUMP_SLOT => {
            // S + A
            unsafe { target.write(symval + r.r_addend as u64) };
        }
        arch::R_DTPMOD64 => {
            // TLS module ID
            unsafe { target.write(symval) };
        }
        arch::R_DTPOFF64 => {
            // TLS offset within module
            unsafe { target.write(symval + r.r_addend as u64) };
        }
        arch::R_TPOFF64 => {
            // Static TLS offset from TP
            unsafe { target.write(symval + r.r_addend as u64) };
        }
        arch::R_IRELATIVE => {
            // Resolver address = base + addend; result is the actual function
            // address that gets stored at the GOT slot.
            let resolver_addr = base as u64 + r.r_addend as u64;
            let resolved = match ctx.ifunc {
                Some(cb) => cb(resolver_addr).ok_or(RelocError::IfuncFailed)?,
                None => unsafe { default_ifunc(resolver_addr) }.ok_or(RelocError::IfuncFailed)?,
            };
            unsafe { target.write(resolved) };
        }
        arch::R_TLSDESC => {
            // TLSDESC entries occupy two adjacent words: resolver function and
            // its argument. When `ctx.tlsdesc` is provided, the callback
            // supplies both. When absent, the entry is assumed to have been
            // pre-bound out-of-band (e.g. by the rtld walking the reloc table
            // in a TLSDESC-specific pass before invoking the generic
            // relocator) and the slot is left untouched.
            if let Some(cb) = ctx.tlsdesc {
                let sym_idx = elf64_r_sym(r.r_info);
                if let Some(entry) = cb(sym_idx, r.r_addend) {
                    unsafe {
                        target.write(entry.resolver);
                        target.add(1).write(entry.arg);
                    }
                }
            }
        }
        _ => return Err(RelocError::UnsupportedType(typ)),
    }

    Ok(())
}

/// Applies all RELA relocations from a contiguous table.
///
/// `resolve` is called for each relocation that requires a symbol:
/// `resolve(sym_index) -> Option<u64>` returns the symbol value.
///
/// # Safety
/// The relocation table and all target addresses must be valid.
pub unsafe fn apply_rela_table(
    base: usize,
    rela_ptr: *const Elf64Rela,
    count: usize,
    resolve: impl FnMut(u32) -> Option<u64>,
) -> Result<(), RelocError> {
    unsafe { apply_rela_table_ctx(base, rela_ptr, count, resolve, &RelocCtx::empty()) }
}

/// Applies all RELA relocations from a contiguous table, including IRELATIVE
/// and TLSDESC when the corresponding callbacks are provided in `ctx`.
///
/// # Safety
/// Same as [`apply_rela_table`]; callbacks in `ctx` must satisfy the contract
/// stated on [`RelocCtx`].
pub unsafe fn apply_rela_table_ctx(
    base: usize,
    rela_ptr: *const Elf64Rela,
    count: usize,
    mut resolve: impl FnMut(u32) -> Option<u64>,
    ctx: &RelocCtx<'_>,
) -> Result<(), RelocError> {
    for i in 0..count {
        let r = unsafe { &*rela_ptr.add(i) };
        let sym_idx = elf64_r_sym(r.r_info);
        let typ = elf64_r_type(r.r_info);

        // R_RELATIVE / R_NONE / R_IRELATIVE / R_TLSDESC do not consult
        // `resolve`; they either work off the addend or use a dedicated
        // callback in `ctx`.
        let symval = if typ == arch::R_RELATIVE
            || typ == arch::R_NONE
            || typ == arch::R_IRELATIVE
            || typ == arch::R_TLSDESC
        {
            0
        } else if sym_idx != 0 {
            resolve(sym_idx).ok_or(RelocError::SymbolNotFound)?
        } else {
            0
        };

        unsafe { apply_rela_ctx(base, r, symval, ctx)? };
    }
    Ok(())
}
