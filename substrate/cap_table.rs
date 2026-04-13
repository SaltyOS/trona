//! Startup capability table — shared primitives for spawners and readers.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! This module is the single home for `TronaCapTableV1` machinery:
//!
//! - **Builder side** ([`CapTableBuilder`]): spawners (init, procmgr)
//!   serialize a child's role→slot map into a scratch page and pass its
//!   VA to the child via `AT_TRONA_CAP_TABLE`.
//! - **Reader side** ([`install_well_known_caps`],
//!   [`runtime_install_from_auxv`]): all three child-side startup paths
//!   (ELF rtld, PE rtld, static-linked CRT) walk the table and populate
//!   the matching `__trona_cap_*` weak symbols in `lib.rs`.
//!
//! Putting builder and reader in the same file keeps the layout contract
//! (magic, version, entry order) and the role→symbol mapping together.
//! Adding a new system role means adding one match arm in
//! [`system_role_target`] and one weak symbol declaration in `lib.rs`
//! (and a getter in `caps`). Raw authority roles (`ROLE_*_AUTHORITY_RAW`)
//! deliberately have no entry in `system_role_target` — they are reached
//! by procmgr via a private helper, not by any public getter.

use crate::consts::kernel::{
    AT_TRONA_CAP_TABLE, ROLE_COM1_IOPORT, ROLE_CONSOLE_CLIENT, ROLE_CSPACE_NTFN, ROLE_FB_UNTYPED,
    ROLE_INITRD_UNTYPED, ROLE_MMSRV_CLIENT, ROLE_NAMESRV_CLIENT, ROLE_PCI_IOPORT,
    ROLE_PROCMGR_CONTROL, ROLE_READINESS_NTFN, ROLE_RSRCSRV_CLIENT, ROLE_SC_CAP, ROLE_SERVICE_EP,
    ROLE_SIGNAL_NTFN, ROLE_VFS_CLIENT, ROLE_WIN32SRV_CLIENT, TRONA_CAP_TABLE_MAGIC,
    TRONA_CAP_TABLE_VERSION,
};
use crate::types::{TronaCapEntryV1, TronaCapTableV1};

// ---------------------------------------------------------------------------
// Builder side
// ---------------------------------------------------------------------------

/// Maximum number of entries the builder can hold. Sized well above the
/// current system-role count (~18) plus typical service-local roles
/// (~6) with headroom for future expansion.
pub const MAX_CAP_TABLE_ENTRIES: usize = 32;

/// Errors surfaced by the builder. Spawners map these to whatever
/// diagnostics their context supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapTableErr {
    /// `push` called after the builder already holds
    /// `MAX_CAP_TABLE_ENTRIES` entries.
    Overflow,
    /// Caller attempted to store a slot number that does not fit in the
    /// 32-bit `TronaCapEntryV1.slot` field.
    SlotOutOfRange,
}

/// Stack-resident serializer. Call `push` repeatedly, then `write_at`
/// once to stamp the header + entries into a scratch page.
pub struct CapTableBuilder {
    entries: [TronaCapEntryV1; MAX_CAP_TABLE_ENTRIES],
    count: usize,
}

impl Default for CapTableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CapTableBuilder {
    /// Construct an empty builder. All entry slots start zero.
    pub const fn new() -> Self {
        Self {
            entries: [TronaCapEntryV1::zeroed(); MAX_CAP_TABLE_ENTRIES],
            count: 0,
        }
    }

    /// Append an entry for `role_id` pointing at `slot` in the child's
    /// cspace. `slot == 0` is treated as "not populated" and is silently
    /// skipped — callers do not have to pre-filter their layout.
    pub fn push(
        &mut self,
        role_id: u32,
        slot: u64,
        rights: u32,
        flags: u32,
    ) -> Result<(), CapTableErr> {
        if slot == 0 {
            crate::udebug!(|_lb| {
                _lb.str(b"[CAPTBL] silent skip role_id=");
                _lb.hex(role_id as u64);
                _lb.str(b" flags=");
                _lb.hex(flags as u64);
                _lb.str(b"\n");
            });
            return Ok(());
        }
        if slot > u32::MAX as u64 {
            return Err(CapTableErr::SlotOutOfRange);
        }
        if self.count >= MAX_CAP_TABLE_ENTRIES {
            return Err(CapTableErr::Overflow);
        }
        self.entries[self.count] = TronaCapEntryV1 {
            role_id,
            slot: slot as u32,
            rights,
            flags,
        };
        self.count += 1;
        Ok(())
    }

    /// Number of entries currently held.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Total bytes that `write_at` will stamp into the scratch page:
    /// the fixed 16-byte header plus 16 bytes per entry.
    pub const fn byte_len(&self) -> usize {
        core::mem::size_of::<TronaCapTableV1>()
            + self.count * core::mem::size_of::<TronaCapEntryV1>()
    }

    /// Write the header and all collected entries contiguously starting
    /// at `scratch_addr`. Returns the number of bytes written (equal to
    /// [`byte_len`](Self::byte_len)).
    ///
    /// # Safety
    /// `scratch_addr` must point to a writable region of at least
    /// `self.byte_len()` bytes, aligned to the natural alignment of
    /// `TronaCapTableV1` (4 bytes). The caller is responsible for
    /// ensuring the mirrored child VA is mapped and reaches the same
    /// bytes.
    pub unsafe fn write_at(&self, scratch_addr: *mut u8) -> usize {
        let header = TronaCapTableV1 {
            magic: TRONA_CAP_TABLE_MAGIC,
            version: TRONA_CAP_TABLE_VERSION,
            count: self.count as u32,
            reserved: 0,
            entries: [],
        };
        // SAFETY: caller promises the destination is writable and large
        // enough. `TronaCapTableV1` and `TronaCapEntryV1` are `#[repr(C)]`
        // plain-old-data, so field-by-field byte writes are sound.
        unsafe {
            core::ptr::write(scratch_addr as *mut TronaCapTableV1, header);
            let entry_ptr =
                scratch_addr.add(core::mem::size_of::<TronaCapTableV1>()) as *mut TronaCapEntryV1;
            for i in 0..self.count {
                core::ptr::write(entry_ptr.add(i), self.entries[i]);
            }
        }
        self.byte_len()
    }
}

// ---------------------------------------------------------------------------
// Reader side
// ---------------------------------------------------------------------------

/// Return `true` if `table_ptr` points to a well-formed cap table (non-null,
/// correct magic, understood version).
pub fn validate(table_ptr: *const TronaCapTableV1) -> bool {
    if table_ptr.is_null() {
        return false;
    }
    // SAFETY: non-null; the caller guarantees the pointer comes from a
    // spawner-produced table or a walk of the child's own auxv vector.
    let header = unsafe { &*table_ptr };
    header.magic == TRONA_CAP_TABLE_MAGIC && header.version == TRONA_CAP_TABLE_VERSION
}

/// Look up the entry for `role` in `table_ptr`. Returns `None` if the table
/// does not validate or the role is absent.
pub fn lookup(table_ptr: *const TronaCapTableV1, role: u32) -> Option<TronaCapEntryV1> {
    if !validate(table_ptr) {
        return None;
    }
    // SAFETY: validate() confirmed non-null + correct magic/version.
    unsafe {
        let header = &*table_ptr;
        let entries = (table_ptr as *const u8).add(core::mem::size_of::<TronaCapTableV1>())
            as *const TronaCapEntryV1;
        for i in 0..header.count as usize {
            let e = &*entries.add(i);
            if e.role_id == role {
                return Some(*e);
            }
        }
    }
    None
}

/// Walk `table_ptr` and install each recognised system role's slot number
/// into the matching `__trona_cap_*` weak symbol in `lib.rs`. After the
/// system sweep, invoke the weak `__trona_svc_caps_install` hook so that a
/// per-service generated `svc_caps` crate (if linked) can populate its own
/// service-local role symbols from the same table.
///
/// Returns the number of entries examined (i.e. `header.count`), or 0 if
/// `table_ptr` failed validation.
///
/// # Safety
/// `table_ptr` must be null or point to a valid `TronaCapTableV1` that
/// remains readable for the duration of the call.
pub unsafe fn install_well_known_caps(table_ptr: *const TronaCapTableV1) -> u32 {
    if !validate(table_ptr) {
        return 0;
    }
    // SAFETY: validated; caller guarantees lifetime.
    unsafe {
        let header = &*table_ptr;
        let entries = (table_ptr as *const u8).add(core::mem::size_of::<TronaCapTableV1>())
            as *const TronaCapEntryV1;
        for i in 0..header.count as usize {
            let e = &*entries.add(i);
            if let Some(target) = system_role_target(e.role_id) {
                core::ptr::write_volatile(target, e.slot as u64);
            }
        }
        // Service-local roles: default weak hook is a no-op.
        __trona_svc_caps_install(table_ptr);
        header.count
    }
}

/// Walk the given auxv vector and return the `AT_TRONA_CAP_TABLE` pointer,
/// or null if absent. Unlike [`runtime_install_from_auxv`] this only
/// reports the address — it does not validate the header or install
/// anything into libtrona weak symbols.
///
/// # Safety
/// `auxv` must be null or point to a properly terminated auxv vector
/// (pairs of u64 values terminated by a tag of 0).
pub unsafe fn find_in_auxv(auxv: *const u64) -> *const TronaCapTableV1 {
    if auxv.is_null() {
        return core::ptr::null();
    }
    // SAFETY: caller guarantees the auxv vector is 0-terminated.
    unsafe {
        let mut p = auxv;
        loop {
            let tag = *p;
            if tag == 0 {
                return core::ptr::null();
            }
            let val = *p.add(1);
            if tag == AT_TRONA_CAP_TABLE && val != 0 {
                return val as *const TronaCapTableV1;
            }
            p = p.add(2);
        }
    }
}

/// Find `AT_TRONA_CAP_TABLE` in the given auxv vector, validate, and install.
/// Returns the entry count installed, or 0 on absence/failure.
///
/// # Safety
/// `auxv` must be null or point to a properly terminated auxv vector (pairs
/// of u64 values terminated by a tag of 0).
pub unsafe fn runtime_install_from_auxv(auxv: *const u64) -> u32 {
    // SAFETY: same contract as `find_in_auxv` — delegated.
    let table = unsafe { find_in_auxv(auxv) };
    if table.is_null() {
        0
    } else {
        // SAFETY: `find_in_auxv` guarantees the pointer came from a
        // valid `AT_TRONA_CAP_TABLE` auxv entry.
        unsafe { install_well_known_caps(table) }
    }
}

/// C ABI entry: rtld (ELF or PE) can call this with its walked auxv
/// pointer without re-implementing the cap-table walker in C.
///
/// # Safety
/// Same contract as [`runtime_install_from_auxv`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn trona_runtime_install_cap_table(auxv: *const u64) -> u32 {
    unsafe { runtime_install_from_auxv(auxv) }
}

/// Default weak hook — no-op. Generated `svc_caps` crates provide a strong
/// override that walks `table_ptr` and stores service-local role slots into
/// per-crate weak symbols.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub extern "C" fn __trona_svc_caps_install(_table_ptr: *const TronaCapTableV1) {}

/// Return a raw pointer to the `__trona_cap_*` weak symbol that backs the
/// given publicly-exposed system `role`, or `None` for roles that either
/// do not live in the public substrate ABI (`ROLE_*_AUTHORITY_RAW`) or are
/// not system roles at all (service-local role IDs >= `LOCAL_ROLE_BASE`).
fn system_role_target(role: u32) -> Option<*mut u64> {
    // `&raw mut` on a `static mut` is safe in Rust 2024 — it produces a
    // raw pointer without creating a reference. The caller performs a
    // single `write_volatile` during startup, before concurrent access is
    // possible, so the subsequent store is sound.
    match role {
        ROLE_PROCMGR_CONTROL => Some(&raw mut crate::__trona_cap_procmgr_ep),
        ROLE_SERVICE_EP => Some(&raw mut crate::__trona_cap_service_ep),
        ROLE_NAMESRV_CLIENT => Some(&raw mut crate::__trona_cap_namesrv_ep),
        ROLE_VFS_CLIENT => Some(&raw mut crate::__trona_cap_vfs_ep),
        ROLE_MMSRV_CLIENT => Some(&raw mut crate::__trona_cap_mmsrv_ep),
        ROLE_RSRCSRV_CLIENT => Some(&raw mut crate::__trona_cap_rsrcsrv_ep),
        ROLE_CONSOLE_CLIENT => Some(&raw mut crate::__trona_cap_console_ep),
        ROLE_SIGNAL_NTFN => Some(&raw mut crate::__trona_cap_signal_ntfn),
        ROLE_READINESS_NTFN => Some(&raw mut crate::__trona_cap_readiness_ntfn),
        ROLE_INITRD_UNTYPED => Some(&raw mut crate::__trona_cap_initrd_untyped),
        ROLE_FB_UNTYPED => Some(&raw mut crate::__trona_cap_fb_untyped),
        ROLE_PCI_IOPORT => Some(&raw mut crate::__trona_cap_pci_ioport),
        ROLE_COM1_IOPORT => Some(&raw mut crate::__trona_cap_com1_ioport),
        ROLE_CSPACE_NTFN => Some(&raw mut crate::__trona_cspace_ntfn),
        ROLE_SC_CAP => Some(&raw mut crate::__trona_sc_cap),
        ROLE_WIN32SRV_CLIENT => Some(&raw mut crate::__trona_cap_win32srv_ep),
        // Raw authority roles are deliberately absent — procmgr reaches
        // them via `cap_table_private::lookup`, not via public getters.
        _ => None,
    }
}
