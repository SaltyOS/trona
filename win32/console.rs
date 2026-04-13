// Win32 console API — direct VFS-backed console I/O for PE binaries.
// SPDX-License-Identifier: GPL-2.0-only

use crate::error::*;
use crate::handle::*;
use crate::trona;

use crate::trona::consts::kernel::*;
use crate::trona::protocol::vfs::*;
use crate::trona::types::core::*;

fn ipc_ctx() -> *mut IpcContext {
    trona::current_ipc_ctx()
}

static mut CONSOLE_INPUT_MODE: DWORD = crate::DEFAULT_INPUT_MODE;
static mut CONSOLE_OUTPUT_MODE: DWORD = crate::DEFAULT_OUTPUT_MODE;

pub unsafe fn reset_console_modes() {
    unsafe {
        *(&raw mut CONSOLE_INPUT_MODE) = crate::DEFAULT_INPUT_MODE;
        *(&raw mut CONSOLE_OUTPUT_MODE) = crate::DEFAULT_OUTPUT_MODE;
    }
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

            let err = trona::ipc::call_ctx(
                ipc_ctx(),
                trona::caps::vfs_ep(),
                &raw const msg,
                &raw mut reply,
            );
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

            let err = trona::ipc::call_ctx(
                ipc_ctx(),
                trona::caps::vfs_ep(),
                &raw const msg,
                &raw mut reply,
            );
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

        let err = trona::ipc::call_ctx(
            ipc_ctx(),
            trona::caps::vfs_ep(),
            &raw const msg,
            &raw mut reply,
        );
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
pub unsafe extern "C" fn SetConsoleMode(
    h_console_handle: HANDLE,
    dw_mode: DWORD,
) -> BOOL {
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
