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
