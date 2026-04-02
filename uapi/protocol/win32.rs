// Win32 subsystem IPC protocol labels.
// SPDX-License-Identifier: GPL-2.0-only
//
// Labels used between Win32 PE processes (via kernel32.dll / trona_win32)
// and the win32_csrss server. POSIX subsystem code must not depend on these.

/// Import resolution: PE rtld sends the import name inline, server returns
/// the matching kernel32 export RVA.
/// Wire: regs[0]=name_len, regs[1]=ordinal_hint, regs[2..]=name bytes.
/// Reply: regs[0]=kernel32_export_rva (0 = not found).
pub const W32_RESOLVE_IMPORT: u64 = 0x100;

/// Console write: inline data in IPC registers.
/// Wire: regs[0]=byte_count, regs[1..]=data bytes.
/// Reply: label=TRONA_OK, regs[0]=bytes_written.
pub const W32_CONSOLE_WRITE: u64 = 0x101;

/// Console read: request bytes from stdin.
/// Wire: regs[0]=max_bytes.
/// Reply: label=TRONA_OK, regs[0]=actual_bytes, regs[1..]=data.
pub const W32_CONSOLE_READ: u64 = 0x102;

/// Get console mode flags for a handle.
/// Wire: regs[0]=console_handle_type (0=input, 1=output).
/// Reply: label=TRONA_OK, regs[0]=mode_flags.
pub const W32_GET_CONSOLE_MODE: u64 = 0x103;

/// Set console mode flags for a handle.
/// Wire: regs[0]=console_handle_type, regs[1]=mode_flags.
/// Reply: label=TRONA_OK.
pub const W32_SET_CONSOLE_MODE: u64 = 0x104;

/// Client registration: PE process announces itself.
/// Wire: (empty).
/// Reply: label=TRONA_OK.
pub const W32_CLIENT_REGISTER: u64 = 0x105;

/// Client exit notification.
/// Wire: regs[0]=exit_code.
/// Reply: label=TRONA_OK.
pub const W32_CLIENT_EXIT: u64 = 0x106;

// Default console mode flags (matching Windows defaults)
pub const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
pub const ENABLE_LINE_INPUT: u32 = 0x0002;
pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
pub const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
pub const ENABLE_WRAP_AT_EOL_OUTPUT: u32 = 0x0002;

pub const DEFAULT_INPUT_MODE: u32 =
    ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
pub const DEFAULT_OUTPUT_MODE: u32 =
    ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;
