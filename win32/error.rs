// Win32 error handling — GetLastError / SetLastError with TLS.
// SPDX-License-Identifier: GPL-2.0-only
//
// Per-thread last-error code, stored in a static (single-threaded for now).
// Maps TRONA_* error codes to Win32 DWORD error codes.

use crate::handle::{BOOL, DWORD, FALSE};

// Win32 error codes
pub const ERROR_SUCCESS: DWORD = 0;
pub const ERROR_INVALID_FUNCTION: DWORD = 1;
pub const ERROR_FILE_NOT_FOUND: DWORD = 2;
pub const ERROR_PATH_NOT_FOUND: DWORD = 3;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_INVALID_HANDLE: DWORD = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: DWORD = 8;
pub const ERROR_INVALID_PARAMETER: DWORD = 87;
pub const ERROR_ALREADY_EXISTS: DWORD = 183;
pub const ERROR_MORE_DATA: DWORD = 234;
pub const ERROR_NO_MORE_ITEMS: DWORD = 259;
pub const ERROR_NOT_SUPPORTED: DWORD = 50;
pub const ERROR_SHARING_VIOLATION: DWORD = 32;
pub const ERROR_BUSY: DWORD = 170;
pub const ERROR_DEVICE_NOT_CONNECTED: DWORD = 1167;

static mut LAST_ERROR: DWORD = 0;

/// Map a kernel-ABI / win32-personality error label to a Win32 error
/// code. Kernel-ABI labels come from the bindgen `uapi` crate; the
/// >=100 personality-wire labels live in `crate::protocol`.
pub fn trona_to_win32_error(trona_err: u64) -> DWORD {
    use trona_protocol::posix::{TRONA_ALREADY_BOUND, TRONA_SERVER_DIED};
    match trona_err {
        x if x == uapi::KERNITE_OK as u64 => ERROR_SUCCESS,
        x if x == uapi::KERNITE_ERR_INVALID_CAPABILITY as u64 => ERROR_INVALID_HANDLE,
        x if x == uapi::KERNITE_ERR_INVALID_OPERATION as u64 => ERROR_INVALID_FUNCTION,
        x if x == uapi::KERNITE_ERR_INSUFFICIENT_RIGHTS as u64 => ERROR_ACCESS_DENIED,
        x if x == uapi::KERNITE_ERR_INVALID_ARGUMENT as u64 => ERROR_INVALID_PARAMETER,
        x if x == uapi::KERNITE_ERR_OUT_OF_MEMORY as u64 => ERROR_NOT_ENOUGH_MEMORY,
        x if x == uapi::KERNITE_ERR_NOT_FOUND as u64 => ERROR_FILE_NOT_FOUND,
        x if x == uapi::KERNITE_ERR_BUSY as u64 => ERROR_BUSY,
        x if x == uapi::KERNITE_ERR_ALREADY_EXISTS as u64 => ERROR_ALREADY_EXISTS,
        x if x == uapi::KERNITE_ERR_SLOT_OCCUPIED as u64 => ERROR_ALREADY_EXISTS,
        x if x == uapi::KERNITE_ERR_ALREADY_MAPPED as u64 => ERROR_ALREADY_EXISTS,
        x if x == TRONA_ALREADY_BOUND => ERROR_BUSY,
        x if x == TRONA_SERVER_DIED => ERROR_DEVICE_NOT_CONNECTED,
        _ => ERROR_INVALID_FUNCTION,
    }
}

pub fn ntstatus_to_win32_error(status: u32) -> DWORD {
    match status {
        trona_protocol::win32::WIN32_STATUS_SUCCESS => ERROR_SUCCESS,
        trona_protocol::win32::WIN32_STATUS_OBJECT_NAME_NOT_FOUND => ERROR_FILE_NOT_FOUND,
        trona_protocol::win32::WIN32_STATUS_OBJECT_PATH_NOT_FOUND => ERROR_PATH_NOT_FOUND,
        trona_protocol::win32::WIN32_STATUS_ACCESS_DENIED => ERROR_ACCESS_DENIED,
        trona_protocol::win32::WIN32_STATUS_INVALID_PARAMETER => ERROR_INVALID_PARAMETER,
        trona_protocol::win32::WIN32_STATUS_NOT_SUPPORTED => ERROR_NOT_SUPPORTED,
        trona_protocol::win32::WIN32_STATUS_SHARING_VIOLATION => ERROR_SHARING_VIOLATION,
        trona_protocol::win32::WIN32_STATUS_NO_MEMORY => ERROR_NOT_ENOUGH_MEMORY,
        trona_protocol::win32::WIN32_STATUS_INVALID_DEVICE_REQUEST => ERROR_INVALID_FUNCTION,
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
    unsafe {
        *(&raw mut LAST_ERROR) = err;
    }
    FALSE
}

/// Internal helper: clear last error (set to ERROR_SUCCESS).
pub(crate) fn clear_error() {
    unsafe {
        *(&raw mut LAST_ERROR) = ERROR_SUCCESS;
    }
}
