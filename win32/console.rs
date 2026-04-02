// Win32 console API — GetStdHandle, WriteConsoleA/W, ReadConsoleA.
// SPDX-License-Identifier: GPL-2.0-only
//
// Console data-path I/O goes directly to VFS using the handle-table slot's
// underlying object slot/fd. CSRSS remains responsible for console mode state.

use crate::error::*;
use crate::handle::*;

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::vfs::*;
use trona::types::core::*;

fn ipc_ctx() -> *mut IpcContext {
    trona::current_ipc_ctx()
}

unsafe fn vfs_write_fd(fd: i32, buf: *const u8, count: u64) -> Result<u64, u64> {
    unsafe {
        let mut total = 0u64;
        while total < count {
            let mut chunk = count - total;
            if chunk > 144 {
                chunk = 144;
            }

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_WRITE;
            msg.length = 2 + ((chunk + 7) / 8);
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;

            let dst = &raw mut msg.regs[2] as *mut u8;
            for i in 0..chunk as usize {
                *dst.add(i) = *buf.add(total as usize + i);
            }

            let err = ipc::call_ctx(ipc_ctx(), CAP_VFS_EP, &raw const msg, &raw mut reply);
            if err != 0 {
                return Err(err as u64);
            }
            if reply.label != TRONA_OK {
                return Err(reply.label);
            }

            let actual = reply.regs[0];
            total += actual;
            if actual < chunk {
                break;
            }
        }
        Ok(total)
    }
}

unsafe fn vfs_read_fd(fd: i32, buf: *mut u8, count: u64) -> Result<u64, u64> {
    unsafe {
        let mut total = 0u64;
        while total < count {
            let mut chunk = count - total;
            if chunk > 152 {
                chunk = 152;
            }

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = VFS_READ;
            msg.length = 2;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;

            let err = ipc::call_ctx(ipc_ctx(), CAP_VFS_EP, &raw const msg, &raw mut reply);
            if err != 0 {
                return Err(err as u64);
            }
            if reply.label != TRONA_OK {
                return Err(reply.label);
            }

            let actual = reply.regs[0];
            if actual == 0 {
                break;
            }

            let src = &raw const reply.regs[1] as *const u8;
            for i in 0..actual as usize {
                *buf.add(total as usize + i) = *src.add(i);
            }

            total += actual;
            if actual < chunk {
                break;
            }
        }
        Ok(total)
    }
}

unsafe fn vfs_close_fd(fd: i32) -> Result<(), u64> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = ipc::call_ctx(ipc_ctx(), CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return Err(err as u64);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn GetStdHandle(n_std_handle: DWORD) -> HANDLE {
    let h = std_handle_to_handle(n_std_handle);
    if h == INVALID_HANDLE_VALUE {
        SetLastError(ERROR_INVALID_HANDLE);
    }
    h
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn WriteConsoleA(
    h_console_output: HANDLE,
    lp_buffer: *const u8,
    n_number_of_chars_to_write: DWORD,
    lp_number_of_chars_written: *mut DWORD,
    _lp_reserved: *const u8,
) -> BOOL {
    unsafe {
        if lp_buffer.is_null() {
            return set_error_return_false(ERROR_INVALID_PARAMETER);
        }

        let entry = match lookup(h_console_output) {
            Some(e) => e,
            None => return set_error_return_false(ERROR_INVALID_HANDLE),
        };
        if entry.kind != HandleKind::VfsFd {
            return set_error_return_false(ERROR_INVALID_HANDLE);
        }

        let written = match vfs_write_fd(entry.vfs_fd, lp_buffer, n_number_of_chars_to_write as u64) {
            Ok(v) => v,
            Err(e) => {
                if !lp_number_of_chars_written.is_null() {
                    *lp_number_of_chars_written = 0;
                }
                return set_trona_error_return_false(e);
            }
        };

        if !lp_number_of_chars_written.is_null() {
            *lp_number_of_chars_written = written as DWORD;
        }
        clear_error();
        TRUE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn WriteConsoleW(
    h_console_output: HANDLE,
    lp_buffer: *const u16,
    n_number_of_chars_to_write: DWORD,
    lp_number_of_chars_written: *mut DWORD,
    lp_reserved: *const u8,
) -> BOOL {
    unsafe {
        if lp_buffer.is_null() {
            return set_error_return_false(ERROR_INVALID_PARAMETER);
        }

        let count = n_number_of_chars_to_write as usize;
        let max = if count > 256 { 256 } else { count };
        let mut ascii_buf = [0u8; 256];
        let mut ascii_len = 0usize;

        for i in 0..max {
            let ch = *lp_buffer.add(i);
            ascii_buf[ascii_len] = if ch < 128 { ch as u8 } else { b'?' };
            ascii_len += 1;
        }

        WriteConsoleA(
            h_console_output,
            ascii_buf.as_ptr(),
            ascii_len as DWORD,
            lp_number_of_chars_written,
            lp_reserved,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ReadConsoleA(
    h_console_input: HANDLE,
    lp_buffer: *mut u8,
    n_number_of_chars_to_read: DWORD,
    lp_number_of_chars_read: *mut DWORD,
    _lp_input_control: *const u8,
) -> BOOL {
    unsafe {
        if lp_buffer.is_null() {
            return set_error_return_false(ERROR_INVALID_PARAMETER);
        }

        let entry = match lookup(h_console_input) {
            Some(e) => e,
            None => return set_error_return_false(ERROR_INVALID_HANDLE),
        };
        if entry.kind != HandleKind::VfsFd {
            return set_error_return_false(ERROR_INVALID_HANDLE);
        }

        let n_read = match vfs_read_fd(entry.vfs_fd, lp_buffer, n_number_of_chars_to_read as u64) {
            Ok(v) => v,
            Err(e) => {
                if !lp_number_of_chars_read.is_null() {
                    *lp_number_of_chars_read = 0;
                }
                return set_trona_error_return_false(e);
            }
        };

        if !lp_number_of_chars_read.is_null() {
            *lp_number_of_chars_read = n_read as DWORD;
        }
        clear_error();
        TRUE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn GetConsoleMode(
    h_console_handle: HANDLE,
    lp_mode: *mut DWORD,
) -> BOOL {
    unsafe {
        if lp_mode.is_null() {
            return set_error_return_false(ERROR_INVALID_PARAMETER);
        }

        let slot = match handle_to_slot(h_console_handle) {
            Some(s) => s,
            None => return set_error_return_false(ERROR_INVALID_HANDLE),
        };

        let handle_type: u64 = if slot == 0 { 0 } else { 1 };
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = crate::W32_GET_CONSOLE_MODE;
        msg.length = 1;
        msg.regs[0] = handle_type;

        let ep = win32srv_ep();
        if ep == 0 {
            *lp_mode = if slot == 0 {
                crate::DEFAULT_INPUT_MODE
            } else {
                crate::DEFAULT_OUTPUT_MODE
            };
            clear_error();
            return TRUE;
        }

        let err = ipc::call_ctx(ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 {
            return set_trona_error_return_false(err as u64);
        }
        if reply.label != TRONA_OK {
            return set_trona_error_return_false(reply.label);
        }

        *lp_mode = reply.regs[0] as DWORD;
        clear_error();
        TRUE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetConsoleMode(
    h_console_handle: HANDLE,
    dw_mode: DWORD,
) -> BOOL {
    unsafe {
        let slot = match handle_to_slot(h_console_handle) {
            Some(s) => s,
            None => return set_error_return_false(ERROR_INVALID_HANDLE),
        };

        let handle_type: u64 = if slot == 0 { 0 } else { 1 };
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = crate::W32_SET_CONSOLE_MODE;
        msg.length = 2;
        msg.regs[0] = handle_type;
        msg.regs[1] = dw_mode as u64;

        let ep = win32srv_ep();
        if ep == 0 {
            clear_error();
            return TRUE;
        }

        let err = ipc::call_ctx(ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 {
            return set_trona_error_return_false(err as u64);
        }
        if reply.label != TRONA_OK {
            return set_trona_error_return_false(reply.label);
        }

        clear_error();
        TRUE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CloseHandle(h_object: HANDLE) -> BOOL {
    unsafe {
        let entry = match lookup(h_object) {
            Some(e) => *e,
            None => return set_error_return_false(ERROR_INVALID_HANDLE),
        };

        if entry.kind == HandleKind::VfsFd && entry.vfs_fd >= 0 {
            if let Err(e) = vfs_close_fd(entry.vfs_fd) {
                return set_trona_error_return_false(e);
            }
        }

        if close_handle(h_object) {
            clear_error();
            TRUE
        } else {
            set_error_return_false(ERROR_INVALID_HANDLE)
        }
    }
}

fn win32srv_ep() -> u64 {
    unsafe { *(&raw const crate::crt::__win32srv_ep) }
}

    /// Win32 ReadConsoleA — read ASCII bytes from a console input handle.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ReadConsoleA(
        h_console_input: HANDLE,
        lp_buffer: *mut u8,
        n_number_of_chars_to_read: DWORD,
        lp_number_of_chars_read: *mut DWORD,
        _lp_input_control: *const u8,
    ) -> BOOL {
        unsafe {
            if lp_buffer.is_null() {
                return set_error_return_false(ERROR_INVALID_PARAMETER);
            }

            let entry = match lookup(h_console_input) {
                Some(e) => e,
                None => return set_error_return_false(ERROR_INVALID_HANDLE),
            };

            if entry.kind != HandleKind::VfsFd {
                return set_error_return_false(ERROR_INVALID_HANDLE);
            }

            let fd = entry.vfs_fd;
            let count = n_number_of_chars_to_read as u64;
            let n_read = match vfs_read_fd(fd, lp_buffer, count) {
                Ok(v) => v,
                Err(e) => {
                    if !lp_number_of_chars_read.is_null() {
                        *lp_number_of_chars_read = 0;
                    }
                    return set_trona_error_return_false(e);
                }
            };

            if !lp_number_of_chars_read.is_null() {
                *lp_number_of_chars_read = n_read as DWORD;
            }
            clear_error();
            TRUE
        }
    }

    /// Win32 GetConsoleMode — retrieve the current console mode.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn GetConsoleMode(
        h_console_handle: HANDLE,
        lp_mode: *mut DWORD,
    ) -> BOOL {
        unsafe {
            if lp_mode.is_null() {
                return set_error_return_false(ERROR_INVALID_PARAMETER);
            }

            let slot = match handle_to_slot(h_console_handle) {
                Some(s) => s,
                None => return set_error_return_false(ERROR_INVALID_HANDLE),
            };

            // Determine handle type: slot 0 = input, slot 1/2 = output
            let handle_type: u64 = if slot == 0 { 0 } else { 1 };

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = crate::W32_GET_CONSOLE_MODE;
            msg.length = 1;
            msg.regs[0] = handle_type;

            let ep = win32srv_ep();
            if ep == 0 {
                *lp_mode = if slot == 0 {
                    crate::DEFAULT_INPUT_MODE
                } else {
                    crate::DEFAULT_OUTPUT_MODE
                };
                clear_error();
                return TRUE;
            }

            let err = ipc::call_ctx(ipc_ctx(), ep, &raw const msg, &raw mut reply);
            if err != 0 {
                return set_trona_error_return_false(err as u64);
            }
            if reply.label != TRONA_OK {
                return set_trona_error_return_false(reply.label);
            }

            *lp_mode = reply.regs[0] as DWORD;
            clear_error();
            TRUE
        }
    }

    /// Win32 SetConsoleMode — set the console mode.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn SetConsoleMode(
        h_console_handle: HANDLE,
        dw_mode: DWORD,
    ) -> BOOL {
        unsafe {
            let slot = match handle_to_slot(h_console_handle) {
                Some(s) => s,
                None => return set_error_return_false(ERROR_INVALID_HANDLE),
            };

            let handle_type: u64 = if slot == 0 { 0 } else { 1 };

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = crate::W32_SET_CONSOLE_MODE;
            msg.length = 2;
            msg.regs[0] = handle_type;
            msg.regs[1] = dw_mode as u64;

            let ep = win32srv_ep();
            if ep == 0 {
                clear_error();
                return TRUE;
            }

            let err = ipc::call_ctx(ipc_ctx(), ep, &raw const msg, &raw mut reply);
            if err != 0 {
                return set_trona_error_return_false(err as u64);
            }
            if reply.label != TRONA_OK {
                return set_trona_error_return_false(reply.label);
            }

            clear_error();
            TRUE
        }
    }

    /// Win32 CloseHandle — close an object handle.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn CloseHandle(h_object: HANDLE) -> BOOL {
        unsafe {
            let entry = match lookup(h_object) {
                Some(e) => *e,
                None => return set_error_return_false(ERROR_INVALID_HANDLE),
            };

            if entry.kind == HandleKind::VfsFd && entry.vfs_fd >= 0 {
                if let Err(e) = vfs_close_fd(entry.vfs_fd) {
                    return set_trona_error_return_false(e);
                }
            }

            if close_handle(h_object) {
                clear_error();
                TRUE
            } else {
                set_error_return_false(ERROR_INVALID_HANDLE)
            }
        }
    }
