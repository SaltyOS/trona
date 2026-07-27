//! Startup capability table — shared primitives for spawners and readers.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! This module is the single home for `SaltyOSCapTableV1` machinery:
//!
//! - **Builder side** ([`CapTableBuilder`]): spawners (init)
//!   serialize a child's role→slot map into a scratch page and pass its
//!   VA to the child via `SaltyOSStartupLayoutV1.cap_table_ptr`.
//! - **Reader side** ([`install_well_known_caps`],
//!   [`runtime_install_from_auxv`]): all three child-side startup paths
//!   (ELF rtld, PE rtld, static-linked CRT) walk the table and populate
//!   the matching `__trona_cap_*` weak symbols in `lib.rs`.
//!
//! Putting builder and reader in the same file keeps the layout contract
//! (magic, version, entry order) and the role→symbol mapping together.
//! Adding a new public runtime getter role means adding one match arm in
//! [`system_role_target`] and one weak symbol declaration in `lib.rs`
//! (and a getter in `caps`). Raw authority roles (`ROLE_*_AUTHORITY_RAW`)
//! deliberately have no entry in `system_role_target` — they are reached
//! by init via a private helper, not by any public getter.

use crate::spawn::role_consts::{
    CAP_TBL_FLAG_RESERVED, ROLE_CLOCK, ROLE_COM1_IOPORT, ROLE_COM1_IRQ, ROLE_COM1_NTFN,
    ROLE_CONSOLE_CLIENT, ROLE_DEVICE_CONTROL, ROLE_FB_UNTYPED, ROLE_INIT_CONTROL,
    ROLE_INITRD_UNTYPED, ROLE_KBD_IOPORT, ROLE_KBD_IRQ, ROLE_KERNEL_DEBUG, ROLE_KERNEL_RNG,
    ROLE_LDSRV_CLIENT, ROLE_LOG_CLIENT, ROLE_MMSRV_CLIENT, ROLE_NAMESRV_CLIENT, ROLE_PCI_IOPORT,
    ROLE_RSRCSRV_CLIENT, ROLE_SC_CAP, ROLE_SERVICE_CLIENT_EP, ROLE_SERVICE_EP, ROLE_SIGNAL_PIPE,
    ROLE_SYSTEM_CONTROL, ROLE_SYSTEM_INFO, ROLE_VFS_CLIENT, ROLE_WIN32SRV_CLIENT,
    SALTYOS_CAP_TABLE_MAGIC, SALTYOS_CAP_TABLE_VERSION,
};
use trona_kernel::core_types::{SaltyOSCapEntryV1, SaltyOSCapTableV1};

// ---------------------------------------------------------------------------
// Builder side
// ---------------------------------------------------------------------------

/// Selftest-only stack-local entry capacity. Production spawn paths
/// use [`CapTableBuilder::new_at`] over a frame-backed scratch buffer.
pub const STACK_LOCAL_MAX_ENTRIES: usize = 32;

/// Errors surfaced by the builder. Spawners map these to whatever
/// diagnostics their context supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapTableErr {
    /// `push` called after the builder filled its capacity. For
    /// frame-backed builders capacity is computed from the underlying
    /// frame size at construction; for selftest stack-local builders it
    /// equals `STACK_LOCAL_MAX_ENTRIES`.
    Overflow,
    /// Caller attempted to store a slot number that does not fit in the
    /// 32-bit `SaltyOSCapEntryV1.slot` field.
    SlotOutOfRange,
    /// Caller attempted to push a role id that is already present in the
    /// builder. Role ids must be unique within a single cap table — a
    /// collision indicates either a genuinely duplicated role or a
    /// service-local djb2 hash clash that the spawner must resolve
    /// before emitting the table.
    DuplicateRole(u32),
}

enum BuilderStorage {
    /// Frame-backed: entries live directly in the destination scratch
    /// frame at `buffer..buffer + capacity * 16`. `finalize` writes the
    /// header at `buffer - sizeof(SaltyOSCapTableV1)`. Capacity is
    /// computed from the frame size — a 4 KiB frame yields 255 entries.
    Frame {
        header: *mut SaltyOSCapTableV1,
        entries: *mut SaltyOSCapEntryV1,
        capacity: usize,
    },
    /// Stack-local: fixed inline array, only used by selftest /
    /// in-process unit checks where allocating + mapping a frame is
    /// disproportionate. Production spawn paths must use Frame.
    StackLocal {
        slots: [SaltyOSCapEntryV1; STACK_LOCAL_MAX_ENTRIES],
    },
}

/// Cap-table serializer. Two storage modes:
///
/// * Frame-backed (production spawn): build directly into the scratch
///   frame the spawner already had to retype + map for the child. No
///   intermediate copy on `finalize`.
/// * Stack-local (selftest only): fixed 32-entry inline array.
pub struct CapTableBuilder {
    storage: BuilderStorage,
    count: usize,
}

impl CapTableBuilder {
    /// Construct a frame-backed builder over `scratch_frame_va`. The
    /// builder reserves the first `sizeof(SaltyOSCapTableV1)` bytes for
    /// the header (written on `finalize`) and lays entries
    /// contiguously after it. `frame_bytes` must be at least
    /// `sizeof(SaltyOSCapTableV1)`; capacity is `(frame_bytes - header) / 16`.
    ///
    /// # Safety
    /// `scratch_frame_va` must point to a writable region of at least
    /// `frame_bytes` bytes, naturally aligned to `SaltyOSCapTableV1`
    /// (4 bytes), and remain mapped until the caller hands the cap
    /// table to the child. The builder writes through this pointer
    /// during `push` and `finalize`.
    pub unsafe fn new_at(scratch_frame_va: *mut u8, frame_bytes: usize) -> Self {
        let header_size = core::mem::size_of::<SaltyOSCapTableV1>();
        let entry_size = core::mem::size_of::<SaltyOSCapEntryV1>();
        let capacity = if frame_bytes > header_size {
            (frame_bytes - header_size) / entry_size
        } else {
            0
        };
        let header = scratch_frame_va as *mut SaltyOSCapTableV1;
        // SAFETY: caller-promised buffer covers header + entries.
        let entries = unsafe { scratch_frame_va.add(header_size) } as *mut SaltyOSCapEntryV1;
        Self {
            storage: BuilderStorage::Frame {
                header,
                entries,
                capacity,
            },
            count: 0,
        }
    }

    /// Construct a stack-local builder for selftest only. Capacity is
    /// fixed at `STACK_LOCAL_MAX_ENTRIES`. Production spawn paths must
    /// not use this — they have a destination frame already and should
    /// build into it directly via `new_at`.
    pub const fn stack_local() -> Self {
        Self {
            storage: BuilderStorage::StackLocal {
                slots: [SaltyOSCapEntryV1::zeroed(); STACK_LOCAL_MAX_ENTRIES],
            },
            count: 0,
        }
    }

    fn capacity(&self) -> usize {
        match &self.storage {
            BuilderStorage::Frame { capacity, .. } => *capacity,
            BuilderStorage::StackLocal { .. } => STACK_LOCAL_MAX_ENTRIES,
        }
    }

    fn entry_at(&self, idx: usize) -> SaltyOSCapEntryV1 {
        match &self.storage {
            // SAFETY: idx < self.count <= capacity, all bytes init.
            BuilderStorage::Frame { entries, .. } => unsafe { core::ptr::read(entries.add(idx)) },
            BuilderStorage::StackLocal { slots } => slots[idx],
        }
    }

    fn write_entry(&mut self, idx: usize, entry: SaltyOSCapEntryV1) {
        match &mut self.storage {
            // SAFETY: idx < capacity (checked by caller).
            BuilderStorage::Frame { entries, .. } => unsafe {
                core::ptr::write(entries.add(idx), entry);
            },
            BuilderStorage::StackLocal { slots } => {
                slots[idx] = entry;
            }
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
        if self.count >= self.capacity() {
            return Err(CapTableErr::Overflow);
        }
        // Reject duplicate role ids — readers treat the table as a
        // role_id → entry map, so two entries with the same id would
        // silently shadow each other. This also catches djb2 hash
        // collisions in `LOCAL_ROLE_BASE + djb2(key) % LOCAL_ROLE_MOD`
        // at the earliest possible moment (spawn time), before any
        // child could observe the ambiguous table.
        for i in 0..self.count {
            if self.entry_at(i).role_id == role_id {
                return Err(CapTableErr::DuplicateRole(role_id));
            }
        }
        self.write_entry(
            self.count,
            SaltyOSCapEntryV1 {
                role_id,
                slot: slot as u32,
                rights,
                flags,
            },
        );
        self.count += 1;
        Ok(())
    }

    /// Number of entries currently held.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Total bytes the table occupies: header + per-entry × count. For
    /// frame-backed builders this is the live region within the scratch
    /// frame; for stack-local it is the byte count `write_at` would
    /// stamp.
    pub const fn byte_len(&self) -> usize {
        core::mem::size_of::<SaltyOSCapTableV1>()
            + self.count * core::mem::size_of::<SaltyOSCapEntryV1>()
    }

    /// Stamp the header at the start of the frame-backed scratch region.
    /// Entries are already in place from `push` calls. Returns
    /// [`byte_len`](Self::byte_len). Frame-backed only.
    ///
    /// # Safety
    /// Builder must be frame-backed (constructed via [`new_at`]) and the
    /// underlying frame must still be mapped + writable.
    pub unsafe fn finalize(&self) -> usize {
        match &self.storage {
            BuilderStorage::Frame { header, .. } => {
                let hdr = SaltyOSCapTableV1 {
                    magic: SALTYOS_CAP_TABLE_MAGIC,
                    version: SALTYOS_CAP_TABLE_VERSION,
                    count: self.count as u32,
                    reserved: 0,
                    entries: [],
                };
                // SAFETY: header pointer is the frame base, alignment
                // and writability promised by `new_at`'s caller.
                unsafe {
                    core::ptr::write(*header, hdr);
                }
                self.byte_len()
            }
            BuilderStorage::StackLocal { .. } => self.byte_len(),
        }
    }

    /// Stack-local fallback: write header + entries to `scratch_addr`.
    /// Only meaningful for `stack_local` builders — frame-backed builders
    /// use [`finalize`](Self::finalize) instead.
    ///
    /// # Safety
    /// `scratch_addr` must point to a writable region of at least
    /// `self.byte_len()` bytes, aligned to `SaltyOSCapTableV1` (4 bytes).
    pub unsafe fn write_at(&self, scratch_addr: *mut u8) -> usize {
        match &self.storage {
            BuilderStorage::Frame { .. } => {
                // Frame builder already lives at its destination —
                // calling `write_at` on it would be a misuse. Caller
                // wants `finalize`.
                unsafe { self.finalize() }
            }
            BuilderStorage::StackLocal { slots } => {
                let header = SaltyOSCapTableV1 {
                    magic: SALTYOS_CAP_TABLE_MAGIC,
                    version: SALTYOS_CAP_TABLE_VERSION,
                    count: self.count as u32,
                    reserved: 0,
                    entries: [],
                };
                // SAFETY: caller promises destination is writable.
                unsafe {
                    core::ptr::write(scratch_addr as *mut SaltyOSCapTableV1, header);
                    let entry_ptr = scratch_addr.add(core::mem::size_of::<SaltyOSCapTableV1>())
                        as *mut SaltyOSCapEntryV1;
                    for i in 0..self.count {
                        core::ptr::write(entry_ptr.add(i), slots[i]);
                    }
                }
                self.byte_len()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reader side
// ---------------------------------------------------------------------------

/// Return `true` if `table_ptr` points to a well-formed cap table (non-null,
/// correct magic, understood version).
pub fn validate(table_ptr: *const SaltyOSCapTableV1) -> bool {
    if table_ptr.is_null() {
        return false;
    }
    // SAFETY: non-null; the caller guarantees the pointer comes from a
    // spawner-produced table or a walk of the child's own auxv vector.
    let header = unsafe { &*table_ptr };
    header.magic == SALTYOS_CAP_TABLE_MAGIC && header.version == SALTYOS_CAP_TABLE_VERSION
}

/// Look up the entry for `role` in `table_ptr`. Returns `None` if the table
/// does not validate or the role is absent.
pub fn lookup(table_ptr: *const SaltyOSCapTableV1, role: u32) -> Option<SaltyOSCapEntryV1> {
    if !validate(table_ptr) {
        return None;
    }
    // SAFETY: validate() confirmed non-null + correct magic/version.
    unsafe {
        let header = &*table_ptr;
        let entries = (table_ptr as *const u8).add(core::mem::size_of::<SaltyOSCapTableV1>())
            as *const SaltyOSCapEntryV1;
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
/// into the matching `__trona_cap_*` weak symbol in `lib.rs`.
///
/// Service-local role IDs (≥ `LOCAL_ROLE_BASE`) are not installed into
/// libtrona globals. Callers resolve them on demand through
/// [`crate::client::caps::local_by_name`] or the `local_cap!` macro, which read
/// directly from the auxv-carried `SaltyOSCapTableV1`.
///
/// Returns the number of entries examined (i.e. `header.count`), or 0 if
/// `table_ptr` failed validation.
///
/// # Safety
/// `table_ptr` must be null or point to a valid `SaltyOSCapTableV1` that
/// remains readable for the duration of the call.
pub unsafe fn install_well_known_caps(table_ptr: *const SaltyOSCapTableV1) -> u32 {
    if !validate(table_ptr) {
        return 0;
    }
    // SAFETY: validated; caller guarantees lifetime.
    unsafe {
        let header = &*table_ptr;
        let entries = (table_ptr as *const u8).add(core::mem::size_of::<SaltyOSCapTableV1>())
            as *const SaltyOSCapEntryV1;
        for i in 0..header.count as usize {
            let e = &*entries.add(i);
            if e.flags & CAP_TBL_FLAG_RESERVED != 0 {
                continue;
            }
            if let Some(target) = system_role_target(e.role_id) {
                core::ptr::write_volatile(target, e.slot as u64);
            }
        }
        header.count
    }
}

/// Walk the given auxv vector and return the startup block's `cap_table`
/// pointer, or null if absent. Unlike [`runtime_install_from_auxv`] this only
/// reports the address — it does not validate the header or install
/// anything into libtrona weak symbols.
///
/// # Safety
/// `auxv` must be null or point to a properly terminated auxv vector
/// (pairs of u64 values terminated by a tag of 0).
pub unsafe fn find_in_auxv(auxv: *const u64) -> *const SaltyOSCapTableV1 {
    if auxv.is_null() {
        return core::ptr::null();
    }
    if let Some(startup) = unsafe { crate::runtime_resolve_startup_from_auxv(auxv) } {
        if startup.cap_table_ptr != 0 {
            return startup.cap_table_ptr as *const SaltyOSCapTableV1;
        }
    }
    core::ptr::null()
}

/// Find the startup block's cap_table in the given auxv vector, validate, and
/// install.
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
        // SAFETY: `find_in_auxv` guarantees the pointer came from the startup
        // block carried in auxv.
        unsafe { install_well_known_caps(table) }
    }
}

/// Reinstall well-known cap-table roles from the saved runtime descriptor's
/// `cap_table_ptr` — the same source `runtime_install` consumes at startup.
///
/// The post-fork child cannot rely on the auxv path alone: its auxv is
/// COW-inherited from the parent and resolves the *parent's* startup block,
/// whose `cap_table_ptr` no longer names the child's freshly-staged cap-table.
/// `__trona_runtime.cap_table_ptr` (also COW-inherited) names the fixed VA at
/// which init stages the child's own cap-table before entering the fork
/// trampoline, so reading roles back through it yields the child's real slots
/// — notably `ROLE_INIT_CONTROL`, without which the child cannot reach init.
/// Returns the entry count installed, or 0 when no cap-table pointer is set.
///
/// # Safety
/// Must run after `__trona_runtime` is populated and the child's cap-table has
/// been staged at its `cap_table_ptr` VA.
pub unsafe fn runtime_reinstall_from_saved_runtime() -> u32 {
    let ptr = unsafe { core::ptr::read_volatile(&raw const crate::__trona_runtime.cap_table_ptr) };
    if ptr == 0 {
        return 0;
    }
    unsafe { install_well_known_caps(ptr as *const SaltyOSCapTableV1) }
}

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
        ROLE_INIT_CONTROL => Some(&raw mut crate::__trona_cap_init_ep),
        ROLE_SERVICE_EP => Some(&raw mut crate::__trona_cap_service_ep),
        ROLE_SERVICE_CLIENT_EP => Some(&raw mut crate::__trona_cap_service_client_ep),
        ROLE_NAMESRV_CLIENT => Some(&raw mut crate::__trona_cap_namesrv_ep),
        ROLE_VFS_CLIENT => Some(&raw mut crate::__trona_cap_vfs_ep),
        ROLE_MMSRV_CLIENT => Some(&raw mut crate::__trona_cap_mmsrv_ep),
        ROLE_RSRCSRV_CLIENT => Some(&raw mut crate::__trona_cap_rsrcsrv_ep),
        ROLE_CONSOLE_CLIENT => Some(&raw mut crate::__trona_cap_console_ep),
        ROLE_LOG_CLIENT => Some(&raw mut crate::__trona_cap_log_ep),
        ROLE_LDSRV_CLIENT => Some(&raw mut crate::__trona_cap_ldsrv_ep),
        ROLE_SIGNAL_PIPE => Some(&raw mut crate::__trona_cap_signal_pipe),
        ROLE_INITRD_UNTYPED => Some(&raw mut crate::__trona_cap_initrd_untyped),
        ROLE_FB_UNTYPED => Some(&raw mut crate::__trona_cap_fb_untyped),
        ROLE_PCI_IOPORT => Some(&raw mut crate::__trona_cap_pci_ioport),
        ROLE_COM1_IOPORT => Some(&raw mut crate::__trona_cap_com1_ioport),
        ROLE_COM1_IRQ => Some(&raw mut crate::__trona_cap_com1_irq),
        ROLE_COM1_NTFN => Some(&raw mut crate::__trona_cap_com1_ntfn),
        ROLE_KBD_IOPORT => Some(&raw mut crate::__trona_cap_kbd_ioport),
        ROLE_KBD_IRQ => Some(&raw mut crate::__trona_cap_kbd_irq),
        ROLE_DEVICE_CONTROL => Some(&raw mut crate::__trona_cap_device_control),
        ROLE_SC_CAP => Some(&raw mut crate::__trona_sc_cap),
        ROLE_WIN32SRV_CLIENT => Some(&raw mut crate::__trona_cap_win32srv_ep),
        ROLE_KERNEL_RNG => Some(&raw mut crate::__trona_cap_kernel_rng),
        ROLE_CLOCK => Some(&raw mut crate::__trona_cap_clock),
        ROLE_SYSTEM_CONTROL => Some(&raw mut crate::__trona_cap_system_control),
        ROLE_SYSTEM_INFO => Some(&raw mut crate::__trona_cap_system_info),
        ROLE_KERNEL_DEBUG => Some(&raw mut crate::__trona_cap_kernel_debug),
        // Raw authority roles + namesrv-private boot roles deliberately
        // absent — consumers reach them via `cap_table_private::lookup`,
        // not via public getters.
        _ => None,
    }
}
