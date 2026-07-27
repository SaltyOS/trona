// SPDX-License-Identifier: GPL-2.0-only
//
//! Win32 personality IPC protocol labels.
//!
//! Used between Win32 PE processes (via kernel32.dll / trona_win32)
//! and the userland servers (init lifecycle, VFS, win32_csrss). POSIX
//! subsystem code must not depend on these labels.

#[cfg(target_os = "saltyos")]
pub use trona_kernel::core_types::{
    SALTYOS_IMAGE_KIND_ELF, SALTYOS_IMAGE_KIND_PE, SALTYOS_STARTUP_MAX_MAPPED_IMAGES,
    SaltyOSImageInfoV1, SaltyOSMappedImageV1,
};

/// Import resolution: PE rtld sends the import name inline, server
/// returns the matching kernel32 export RVA.
///
/// Wire: `regs[0]=name_len`, `regs[1]=ordinal_hint`,
/// `regs[2..]=name bytes`. Reply: `regs[0]=kernel32_export_rva`
/// (`0` = not found).
pub const W32_RESOLVE_IMPORT: u64 = 0x100;

// ---------------------------------------------------------------------------
// init supervisor — kernel32.dll calls these for Win32 process lifecycle.
// Numeric values mirror the canonical init wire layout in
// `lib/trona/substrate/protocol.rs` (`INIT_*` block at `0x100..=0x1FF`) so
// the same init server handles POSIX and Win32 processes side-by-side.
// ---------------------------------------------------------------------------

pub const INIT_EXIT: u64 = 0x105;
pub const INIT_GETPID: u64 = 0x106;

// ---------------------------------------------------------------------------
// VFS server — kernel32.dll routes file APIs through the VFS Win32 / NT
// personality range (`0x540..=0x57F`).
// ---------------------------------------------------------------------------

pub const WIN32_NT_CREATE_FILE: u64 = 0x540;
pub const WIN32_NT_OPEN_FILE: u64 = 0x541;
pub const WIN32_NT_CLOSE: u64 = 0x542;
pub const WIN32_NT_READ_FILE: u64 = 0x543;
pub const WIN32_NT_WRITE_FILE: u64 = 0x544;
pub const WIN32_NT_QUERY_INFORMATION_FILE: u64 = 0x545;
pub const WIN32_NT_SET_INFORMATION_FILE: u64 = 0x546;
pub const WIN32_NT_QUERY_DIRECTORY_FILE: u64 = 0x547;
pub const WIN32_NT_DEVICE_IO_CONTROL_FILE: u64 = 0x548;
pub const WIN32_NT_FLUSH_BUFFERS_FILE: u64 = 0x549;
pub const WIN32_NT_LOCK_FILE: u64 = 0x54A;
pub const WIN32_NT_UNLOCK_FILE: u64 = 0x54B;
pub const WIN32_NT_QUERY_VOLUME_INFORMATION_FILE: u64 = 0x54C;
pub const WIN32_NT_SET_VOLUME_INFORMATION_FILE: u64 = 0x54D;
pub const WIN32_NT_DUPLICATE_OBJECT: u64 = 0x54E;
pub const WIN32_NT_CREATE_PIPE: u64 = 0x54F;
pub const WIN32_NT_CREATE_NAMED_PIPE_FILE: u64 = 0x550;
pub const WIN32_NT_CREATE_MAILSLOT_FILE: u64 = 0x551;
pub const WIN32_NT_CREATE_SYMBOLIC_LINK_OBJECT: u64 = 0x552;
pub const WIN32_NT_CREATE_SECTION: u64 = 0x553;
pub const WIN32_NT_OPEN_SECTION: u64 = 0x554;
pub const WIN32_NT_MAP_VIEW_OF_SECTION: u64 = 0x555;
pub const WIN32_NT_UNMAP_VIEW_OF_SECTION: u64 = 0x556;
pub const WIN32_NT_DELETE_FILE: u64 = 0x557;
pub const WIN32_NT_QUERY_ATTRIBUTES_FILE: u64 = 0x558;
pub const WIN32_NT_QUERY_FULL_ATTRIBUTES_FILE: u64 = 0x559;
pub const WIN32_NT_RENAME_FILE: u64 = 0x55A;
pub const WIN32_NT_QUERY_SECURITY_OBJECT: u64 = 0x55B;
pub const WIN32_NT_SET_SECURITY_OBJECT: u64 = 0x55C;

// ---------------------------------------------------------------------------
// Win32 NT wire constants shared by kernel32.dll clients and VFS's Win32
// personality. These are protocol values, not VFS implementation details.
// ---------------------------------------------------------------------------

pub const WIN32_STATUS_SUCCESS: u32 = 0x0000_0000;
pub const WIN32_STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const WIN32_STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const WIN32_STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const WIN32_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const WIN32_STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const WIN32_STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
pub const WIN32_STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const WIN32_STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;

pub const WIN32_GENERIC_READ: u32 = 0x8000_0000;
pub const WIN32_GENERIC_WRITE: u32 = 0x4000_0000;
pub const WIN32_FILE_SHARE_READ: u32 = 0x0000_0001;
pub const WIN32_FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub const WIN32_FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

// ---------------------------------------------------------------------------
// Reply convention. Win32-personality wire-error labels (>= 100) match the
// numeric layout used by the POSIX personality so the same init/VFS server
// can return identical labels to either side.
// ---------------------------------------------------------------------------

/// Reply label that init / VFS echo back in `TronaMsg.label` to mark
/// "request succeeded". Userland convention — independent of the kernel
/// ABI's `KERNITE_OK` error code (which happens to share the value 0).
pub const TRONA_OK: u64 = 0;

pub const TRONA_ALREADY_BOUND: u64 = 100;
pub const TRONA_SERVER_DIED: u64 = 115;

// Default console mode flags (matching Windows defaults).
pub const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
pub const ENABLE_LINE_INPUT: u32 = 0x0002;
pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
pub const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
pub const ENABLE_WRAP_AT_EOL_OUTPUT: u32 = 0x0002;

pub const DEFAULT_INPUT_MODE: u32 = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
pub const DEFAULT_OUTPUT_MODE: u32 = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;
