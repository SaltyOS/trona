// Win32 console API — direct VFS-backed console I/O for PE binaries.
// SPDX-License-Identifier: GPL-2.0-only

use crate::error::*;
use crate::handle::*;
use crate::ipc;
use crate::runtime;
use crate::types::{IpcContext, TronaMsg};
use trona_protocol::win32::{
    DEFAULT_INPUT_MODE, DEFAULT_OUTPUT_MODE, TRONA_OK, WIN32_FILE_NON_DIRECTORY_FILE,
    WIN32_FILE_SHARE_READ, WIN32_FILE_SHARE_WRITE, WIN32_GENERIC_READ, WIN32_GENERIC_WRITE,
    WIN32_NT_CLOSE, WIN32_NT_OPEN_FILE, WIN32_NT_READ_FILE, WIN32_NT_WRITE_FILE,
    WIN32_STATUS_SUCCESS,
};

fn ipc_ctx() -> *mut IpcContext {
    runtime::current_ipc_ctx()
}

static mut CONSOLE_INPUT_MODE: DWORD = DEFAULT_INPUT_MODE;
static mut CONSOLE_OUTPUT_MODE: DWORD = DEFAULT_OUTPUT_MODE;

pub unsafe fn reset_console_modes() {
    unsafe {
        *(&raw mut CONSOLE_INPUT_MODE) = DEFAULT_INPUT_MODE;
        *(&raw mut CONSOLE_OUTPUT_MODE) = DEFAULT_OUTPUT_MODE;
    }
}

unsafe fn write_bytes_at(msg: &mut TronaMsg, byte_off: usize, src: *const u8, len: usize) {
    unsafe {
        let dst = (msg.regs.as_mut_ptr() as *mut u8).add(byte_off);
        for i in 0..len {
            *dst.add(i) = *src.add(i);
        }
    }
}

fn write_u16_at(msg: &mut TronaMsg, byte_off: usize, value: u16) {
    let bytes = value.to_le_bytes();
    unsafe { write_bytes_at(msg, byte_off, bytes.as_ptr(), bytes.len()) };
}

fn write_u32_at(msg: &mut TronaMsg, byte_off: usize, value: u32) {
    let bytes = value.to_le_bytes();
    unsafe { write_bytes_at(msg, byte_off, bytes.as_ptr(), bytes.len()) };
}

fn write_u64_at(msg: &mut TronaMsg, byte_off: usize, value: u64) {
    let bytes = value.to_le_bytes();
    unsafe { write_bytes_at(msg, byte_off, bytes.as_ptr(), bytes.len()) };
}

fn nt_status(reply: &TronaMsg) -> u32 {
    (reply.regs[0] & 0xFFFF_FFFF) as u32
}

fn nt_information(reply: &TronaMsg) -> u64 {
    reply.regs[1]
}

fn call_error_to_win32(err: i32) -> DWORD {
    crate::error::trona_to_win32_error(err as u64)
}

fn reply_error_to_win32(reply: &TronaMsg) -> DWORD {
    if reply.label != TRONA_OK {
        return crate::error::trona_to_win32_error(reply.label);
    }
    crate::error::ntstatus_to_win32_error(nt_status(reply))
}

unsafe fn nt_open_console_fd(input: bool) -> Result<i32, DWORD> {
    unsafe {
        let path: &[u8] = if input { b"CONIN$" } else { b"CONOUT$" };
        let mut path_utf16 = [0u8; 16];
        for i in 0..path.len() {
            path_utf16[i * 2] = path[i];
            path_utf16[i * 2 + 1] = 0;
        }
        let path_bytes = path.len() * 2;
        let desired = if input {
            WIN32_GENERIC_READ
        } else {
            WIN32_GENERIC_WRITE
        };
        let share = WIN32_FILE_SHARE_READ | WIN32_FILE_SHARE_WRITE;

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = WIN32_NT_OPEN_FILE;
        msg.length = ((48 + path_bytes + 7) / 8) as u64;
        msg.regs[0] = desired as u64 | ((share as u64) << 32);
        msg.regs[1] = WIN32_FILE_NON_DIRECTORY_FILE as u64;

        write_u32_at(&mut msg, 16, 24);
        write_u64_at(&mut msg, 24, 0);
        write_u32_at(&mut msg, 32, 0);
        write_u32_at(&mut msg, 36, 0);
        write_u16_at(&mut msg, 40, path_bytes as u16);
        write_u16_at(&mut msg, 42, path_bytes as u16);
        write_u32_at(&mut msg, 44, 0);
        write_bytes_at(&mut msg, 48, path_utf16.as_ptr(), path_bytes);

        let err = ipc::mp_call_ctx(
            ipc_ctx(),
            runtime::caps::vfs_ep(),
            &raw const msg,
            &raw mut reply,
            crate::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error_to_win32(err));
        }
        if reply.label != TRONA_OK || nt_status(&reply) != WIN32_STATUS_SUCCESS {
            return Err(reply_error_to_win32(&reply));
        }
        Ok(reply.regs[2] as i32)
    }
}

unsafe fn ensure_console_handle(n_std_handle: DWORD) -> Result<HANDLE, DWORD> {
    unsafe {
        let h = std_handle_to_handle(n_std_handle);
        if h == INVALID_HANDLE_VALUE {
            return Err(ERROR_INVALID_HANDLE);
        }
        let slot = handle_to_slot(h).ok_or(ERROR_INVALID_HANDLE)?;
        let entry = lookup(h).ok_or(ERROR_INVALID_HANDLE)?;
        if entry.kind != HandleKind::VfsFd {
            return Err(ERROR_INVALID_HANDLE);
        }
        if entry.vfs_fd >= 0 {
            return Ok(h);
        }
        let fd = nt_open_console_fd(n_std_handle == STD_INPUT_HANDLE)?;
        if !set_vfs_fd_slot(slot, fd) {
            return Err(ERROR_INVALID_HANDLE);
        }
        Ok(h)
    }
}

unsafe fn vfs_fd_for_handle(h: HANDLE) -> Result<i32, DWORD> {
    unsafe {
        let slot = handle_to_slot(h).ok_or(ERROR_INVALID_HANDLE)?;
        let entry = lookup(h).ok_or(ERROR_INVALID_HANDLE)?;
        if entry.kind != HandleKind::VfsFd {
            return Err(ERROR_INVALID_HANDLE);
        }
        if entry.vfs_fd >= 0 {
            return Ok(entry.vfs_fd);
        }
        if slot > 2 {
            return Err(ERROR_INVALID_HANDLE);
        }
        let fd = nt_open_console_fd(slot == 0)?;
        if !set_vfs_fd_slot(slot, fd) {
            return Err(ERROR_INVALID_HANDLE);
        }
        Ok(fd)
    }
}

unsafe fn nt_write_fd(fd: i32, buf: *const u8, count: u64) -> Result<u64, DWORD> {
    unsafe {
        let mut total = 0u64;
        while total < count {
            let mut chunk = count - total;
            if chunk > 144 {
                chunk = 144;
            }

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = WIN32_NT_WRITE_FILE;
            msg.length = 4 + ((chunk + 7) / 8);
            msg.regs[0] = (fd as u32 as u64) | (chunk << 32);
            msg.regs[1] = u64::MAX;
            msg.regs[2] = 0;

            let dst = &raw mut msg.regs[4] as *mut u8;
            for i in 0..chunk as usize {
                *dst.add(i) = *buf.add(total as usize + i);
            }

            let err = ipc::mp_call_ctx(
                ipc_ctx(),
                runtime::caps::vfs_ep(),
                &raw const msg,
                &raw mut reply,
                crate::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 {
                return Err(call_error_to_win32(err));
            }
            if reply.label != TRONA_OK || nt_status(&reply) != WIN32_STATUS_SUCCESS {
                return Err(reply_error_to_win32(&reply));
            }

            let actual = nt_information(&reply);
            total += actual;
            if actual < chunk {
                break;
            }
        }
        Ok(total)
    }
}

unsafe fn nt_read_fd(fd: i32, buf: *mut u8, count: u64) -> Result<u64, DWORD> {
    unsafe {
        let mut total = 0u64;
        while total < count {
            let mut chunk = count - total;
            if chunk > 152 {
                chunk = 152;
            }

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = WIN32_NT_READ_FILE;
            msg.length = 4;
            msg.regs[0] = (fd as u32 as u64) | (chunk << 32);
            msg.regs[1] = u64::MAX;
            msg.regs[2] = 0;

            let err = ipc::mp_call_ctx(
                ipc_ctx(),
                runtime::caps::vfs_ep(),
                &raw const msg,
                &raw mut reply,
                crate::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 {
                return Err(call_error_to_win32(err));
            }
            if reply.label != TRONA_OK || nt_status(&reply) != WIN32_STATUS_SUCCESS {
                return Err(reply_error_to_win32(&reply));
            }

            let actual = nt_information(&reply);
            if actual == 0 {
                break;
            }

            let src = &raw const reply.regs[2] as *const u8;
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

unsafe fn nt_close_fd(fd: i32) -> Result<(), DWORD> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = WIN32_NT_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u32 as u64;

        let err = ipc::mp_call_ctx(
            ipc_ctx(),
            runtime::caps::vfs_ep(),
            &raw const msg,
            &raw mut reply,
            crate::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error_to_win32(err));
        }
        if reply.label != TRONA_OK || nt_status(&reply) != WIN32_STATUS_SUCCESS {
            return Err(reply_error_to_win32(&reply));
        }
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn GetStdHandle(n_std_handle: DWORD) -> HANDLE {
    match unsafe { ensure_console_handle(n_std_handle) } {
        Ok(h) => h,
        Err(e) => {
            SetLastError(e);
            INVALID_HANDLE_VALUE
        }
    }
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

        let fd = match vfs_fd_for_handle(h_console_output) {
            Ok(fd) => fd,
            Err(e) => {
                if !lp_number_of_chars_written.is_null() {
                    *lp_number_of_chars_written = 0;
                }
                return set_error_return_false(e);
            }
        };

        let written = match nt_write_fd(fd, lp_buffer, n_number_of_chars_to_write as u64) {
            Ok(v) => v,
            Err(e) => {
                if !lp_number_of_chars_written.is_null() {
                    *lp_number_of_chars_written = 0;
                }
                return set_error_return_false(e);
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

        let fd = match vfs_fd_for_handle(h_console_input) {
            Ok(fd) => fd,
            Err(e) => {
                if !lp_number_of_chars_read.is_null() {
                    *lp_number_of_chars_read = 0;
                }
                return set_error_return_false(e);
            }
        };

        let n_read = match nt_read_fd(fd, lp_buffer, n_number_of_chars_to_read as u64) {
            Ok(v) => v,
            Err(e) => {
                if !lp_number_of_chars_read.is_null() {
                    *lp_number_of_chars_read = 0;
                }
                return set_error_return_false(e);
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
pub unsafe extern "C" fn GetConsoleMode(h_console_handle: HANDLE, lp_mode: *mut DWORD) -> BOOL {
    unsafe {
        if lp_mode.is_null() {
            return set_error_return_false(ERROR_INVALID_PARAMETER);
        }

        let slot = match handle_to_slot(h_console_handle) {
            Some(s) => s,
            None => return set_error_return_false(ERROR_INVALID_HANDLE),
        };

        *lp_mode = if slot == 0 {
            *(&raw const CONSOLE_INPUT_MODE)
        } else {
            *(&raw const CONSOLE_OUTPUT_MODE)
        };
        clear_error();
        TRUE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetConsoleMode(h_console_handle: HANDLE, dw_mode: DWORD) -> BOOL {
    unsafe {
        let slot = match handle_to_slot(h_console_handle) {
            Some(s) => s,
            None => return set_error_return_false(ERROR_INVALID_HANDLE),
        };

        if slot == 0 {
            *(&raw mut CONSOLE_INPUT_MODE) = dw_mode;
        } else {
            *(&raw mut CONSOLE_OUTPUT_MODE) = dw_mode;
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
            if let Err(e) = nt_close_fd(entry.vfs_fd) {
                return set_error_return_false(e);
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
