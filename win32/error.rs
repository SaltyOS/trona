// Win32 error handling — GetLastError / SetLastError with TLS.
// SPDX-License-Identifier: GPL-2.0-only
//
// Per-thread last-error code, stored in a static (single-threaded for now).
// Maps TRONA_* error codes to Win32 DWORD error codes.

use crate::handle::{BOOL, DWORD, FALSE, TRUE};
use crate::trona;

// Win32 error codes
pub const ERROR_SUCCESS: DWORD = 0;
pub const ERROR_INVALID_FUNCTION: DWORD = 1;
pub const ERROR_FILE_NOT_FOUND: DWORD = 2;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_INVALID_HANDLE: DWORD = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: DWORD = 8;
pub const ERROR_INVALID_PARAMETER: DWORD = 87;
pub const ERROR_ALREADY_EXISTS: DWORD = 183;
pub const ERROR_MORE_DATA: DWORD = 234;
pub const ERROR_NO_MORE_ITEMS: DWORD = 259;
pub const ERROR_BUSY: DWORD = 170;

static mut LAST_ERROR: DWORD = 0;

/// Map a TRONA error code to a Win32 error code.
pub fn trona_to_win32_error(trona_err: u64) -> DWORD {
    use crate::trona::consts::kernel::*;
    match trona_err {
        TRONA_OK => ERROR_SUCCESS,
        TRONA_INVALID_CAPABILITY => ERROR_INVALID_HANDLE,
        TRONA_INVALID_OPERATION => ERROR_INVALID_FUNCTION,
        TRONA_INSUFFICIENT_RIGHTS => ERROR_ACCESS_DENIED,
        TRONA_INVALID_ARGUMENT => ERROR_INVALID_PARAMETER,
        TRONA_OUT_OF_MEMORY => ERROR_NOT_ENOUGH_MEMORY,
        TRONA_NOT_FOUND => ERROR_FILE_NOT_FOUND,
        TRONA_BUSY => ERROR_BUSY,
        TRONA_ALREADY_EXISTS => ERROR_ALREADY_EXISTS,
        TRONA_SLOT_OCCUPIED => ERROR_ALREADY_EXISTS,
        TRONA_ALREADY_MAPPED => ERROR_ALREADY_EXISTS,
        TRONA_ALREADY_BOUND => ERROR_BUSY,
        _ => ERROR_INVALID_FUNCTION,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn GetLastError() -> DWORD {
    unsafe { *(&raw const LAST_ERROR) }
}

#[unsafe(no_mangle)]
pub extern "C" fn SetLastError(dw_err_code: DWORD) {
    unsafe {
        *(&raw mut LAST_ERROR) = dw_err_code;
    }
}

/// Internal helper: set last error and return FALSE.
pub(crate) fn set_error_return_false(err: DWORD) -> BOOL {
    unsafe { *(&raw mut LAST_ERROR) = err; }
    FALSE
}

/// Internal helper: set last error from a TRONA error code and return FALSE.
pub(crate) fn set_trona_error_return_false(trona_err: u64) -> BOOL {
    set_error_return_false(trona_to_win32_error(trona_err))
}

/// Internal helper: clear last error (set to ERROR_SUCCESS).
pub(crate) fn clear_error() {
    unsafe { *(&raw mut LAST_ERROR) = ERROR_SUCCESS; }
}
