// Win32 handle table — client-side handle management.
// SPDX-License-Identifier: GPL-2.0-only
//
// HANDLE encoding: (slot * 4) + 4, so HANDLE 4 = slot 0, HANDLE 8 = slot 1.
// STD_INPUT_HANDLE (-10), STD_OUTPUT_HANDLE (-11), STD_ERROR_HANDLE (-12)
// map to slots 0, 1, 2 respectively.

/// Win32 HANDLE type (pointer-width, matches Windows ABI).
pub type HANDLE = isize;
pub type DWORD = u32;
pub type BOOL = i32;

pub const INVALID_HANDLE_VALUE: HANDLE = -1;
pub const STD_INPUT_HANDLE: DWORD = 0xFFFF_FFF6;  // -10 as u32
pub const STD_OUTPUT_HANDLE: DWORD = 0xFFFF_FFF5;  // -11 as u32
pub const STD_ERROR_HANDLE: DWORD = 0xFFFF_FFF4;   // -12 as u32

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

const MAX_HANDLES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandleKind {
    Free = 0,
    VfsFd = 1,
    CapSlot = 2,
    ServerObject = 3,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct HandleEntry {
    pub kind: HandleKind,
    pub vfs_fd: i32,
    pub cap_slot: u64,
}

impl HandleEntry {
    pub const fn zeroed() -> Self {
        HandleEntry {
            kind: HandleKind::Free,
            vfs_fd: -1,
            cap_slot: 0,
        }
    }

    pub fn is_free(&self) -> bool {
        matches!(self.kind, HandleKind::Free)
    }
}

static mut HANDLE_TABLE: [HandleEntry; MAX_HANDLES] = [HandleEntry::zeroed(); MAX_HANDLES];
static mut HANDLE_TABLE_INIT: bool = false;

unsafe fn seed_std_handles() {
    unsafe {
        let table = &raw mut HANDLE_TABLE;
        for i in 0..MAX_HANDLES {
            (*table)[i] = HandleEntry::zeroed();
        }
        (*table)[0] = HandleEntry { kind: HandleKind::VfsFd, vfs_fd: 0, cap_slot: 0 };
        (*table)[1] = HandleEntry { kind: HandleKind::VfsFd, vfs_fd: 1, cap_slot: 0 };
        (*table)[2] = HandleEntry { kind: HandleKind::VfsFd, vfs_fd: 2, cap_slot: 0 };
    }
}

/// Initialize the handle table with standard I/O handles.
/// Slot 0 = stdin (VFS fd 0), Slot 1 = stdout (VFS fd 1), Slot 2 = stderr (VFS fd 2).
pub unsafe fn init_handle_table() {
    unsafe {
        if *(&raw const HANDLE_TABLE_INIT) {
            return;
        }
        seed_std_handles();
        *(&raw mut HANDLE_TABLE_INIT) = true;
    }
}

pub unsafe fn reset_handle_table() {
    unsafe {
        seed_std_handles();
        *(&raw mut HANDLE_TABLE_INIT) = true;
    }
}

/// Convert a HANDLE value to a slot index.
/// Returns None for invalid handles.
pub fn handle_to_slot(h: HANDLE) -> Option<usize> {
    if h < 4 || (h - 4) % 4 != 0 {
        return None;
    }
    let slot = ((h - 4) / 4) as usize;
    if slot >= MAX_HANDLES {
        return None;
    }
    Some(slot)
}

/// Convert a slot index to a HANDLE value.
pub fn slot_to_handle(slot: usize) -> HANDLE {
    ((slot * 4) + 4) as HANDLE
}

/// Resolve STD_*_HANDLE constants to their HANDLE values.
pub fn std_handle_to_handle(n_std_handle: DWORD) -> HANDLE {
    match n_std_handle {
        STD_INPUT_HANDLE => slot_to_handle(0),   // HANDLE = 4
        STD_OUTPUT_HANDLE => slot_to_handle(1),   // HANDLE = 8
        STD_ERROR_HANDLE => slot_to_handle(2),    // HANDLE = 12
        _ => INVALID_HANDLE_VALUE,
    }
}

/// Look up a handle entry by HANDLE value.
/// Returns None for invalid or free handles.
pub unsafe fn lookup(h: HANDLE) -> Option<&'static HandleEntry> {
    let slot = handle_to_slot(h)?;
    unsafe {
        let table = &raw const HANDLE_TABLE;
        let entry = &(*table)[slot];
        if entry.is_free() {
            return None;
        }
        Some(entry)
    }
}

/// Allocate a new handle entry with the given kind and VFS fd.
/// Returns the HANDLE value, or INVALID_HANDLE_VALUE on failure.
pub unsafe fn alloc_vfs_fd(fd: i32) -> HANDLE {
    unsafe {
        let table = &raw mut HANDLE_TABLE;
        for i in 3..MAX_HANDLES {
            if (*table)[i].is_free() {
                (*table)[i] = HandleEntry {
                    kind: HandleKind::VfsFd,
                    vfs_fd: fd,
                    cap_slot: 0,
                };
                return slot_to_handle(i);
            }
        }
        INVALID_HANDLE_VALUE
    }
}

/// Close a handle, freeing the slot.
pub unsafe fn close_handle(h: HANDLE) -> bool {
    let slot = match handle_to_slot(h) {
        Some(s) => s,
        None => return false,
    };
    unsafe {
        let table = &raw mut HANDLE_TABLE;
        if (*table)[slot].is_free() {
            return false;
        }
        (*table)[slot] = HandleEntry::zeroed();
        true
    }
}
