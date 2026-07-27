//! Personality-neutral filesystem IPC helpers.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! These are substrate-level VFS clients. They intentionally return SaltyOS
//! `TRONA_*` labels instead of POSIX errno values so rtld, POSIX, and other
//! personalities can share the same primitives without depending on each
//! other.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;
use trona_protocol::vfs::public::*;
use trona_protocol::win32::{WIN32_NT_CLOSE, WIN32_NT_OPEN_FILE, WIN32_NT_READ_FILE};

pub type Result<T> = core::result::Result<T, u64>;

const OPEN_READONLY: i32 = 0;

const NT_FILE_READ_DATA: u32 = 0x0000_0001;
const NT_FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const NT_FILE_SHARE_READ: u32 = 0x0000_0001;
const NT_OBJECT_ATTRIBUTES_LEN: u32 = 24;
const NT_OPEN_OA_BYTE_OFF: usize = 16;
const NT_OPEN_US_BYTE_OFF: usize = 40;
const NT_OPEN_PATH_BYTE_OFF: usize = 48;
const NT_INLINE_READ_MAX: u64 = 224;

#[inline]
fn call_error(err: i32) -> u64 {
    err as u64
}

unsafe fn pack_path(msg: *mut TronaMsg, offset: usize, path: *const u8, max_len: usize) -> u8 {
    unsafe {
        let avail = (20usize.saturating_sub(offset + 1)) * 8;
        let cap = if max_len < 128 { max_len } else { 128 };
        let limit = if cap < avail { cap } else { avail };
        let mut path_len: u8 = 0;
        while (path_len as usize) < limit && *path.add(path_len as usize) != 0 {
            path_len += 1;
        }
        let regs = &mut (*msg).regs;
        regs[offset] = path_len as u64;
        for i in (offset + 1)..20 {
            regs[i] = 0;
        }
        let dst = &mut regs[offset + 1] as *mut u64 as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path.add(i);
        }
        path_len
    }
}

fn write_u16(dst: &mut [u8], off: usize, value: u16) -> bool {
    if off + 2 > dst.len() {
        return false;
    }
    dst[off..off + 2].copy_from_slice(&value.to_le_bytes());
    true
}

fn write_u32(dst: &mut [u8], off: usize, value: u32) -> bool {
    if off + 4 > dst.len() {
        return false;
    }
    dst[off..off + 4].copy_from_slice(&value.to_le_bytes());
    true
}

fn write_u64(dst: &mut [u8], off: usize, value: u64) -> bool {
    if off + 8 > dst.len() {
        return false;
    }
    dst[off..off + 8].copy_from_slice(&value.to_le_bytes());
    true
}

unsafe fn utf8_to_utf16le(src: *const u8, len: usize, dst: &mut [u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut out = 0usize;
    while i < len {
        let b0 = unsafe { *src.add(i) };
        let (cp, used) = if b0 < 0x80 {
            (b0 as u32, 1usize)
        } else if (b0 & 0xE0) == 0xC0 {
            if i + 1 >= len {
                return None;
            }
            let b1 = unsafe { *src.add(i + 1) };
            if (b1 & 0xC0) != 0x80 {
                return None;
            }
            let cp = (((b0 & 0x1F) as u32) << 6) | ((b1 & 0x3F) as u32);
            if cp < 0x80 {
                return None;
            }
            (cp, 2)
        } else if (b0 & 0xF0) == 0xE0 {
            if i + 2 >= len {
                return None;
            }
            let b1 = unsafe { *src.add(i + 1) };
            let b2 = unsafe { *src.add(i + 2) };
            if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 {
                return None;
            }
            let cp =
                (((b0 & 0x0F) as u32) << 12) | (((b1 & 0x3F) as u32) << 6) | ((b2 & 0x3F) as u32);
            if cp < 0x800 || (0xD800..=0xDFFF).contains(&cp) {
                return None;
            }
            (cp, 3)
        } else if (b0 & 0xF8) == 0xF0 {
            if i + 3 >= len {
                return None;
            }
            let b1 = unsafe { *src.add(i + 1) };
            let b2 = unsafe { *src.add(i + 2) };
            let b3 = unsafe { *src.add(i + 3) };
            if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
                return None;
            }
            let cp = (((b0 & 0x07) as u32) << 18)
                | (((b1 & 0x3F) as u32) << 12)
                | (((b2 & 0x3F) as u32) << 6)
                | ((b3 & 0x3F) as u32);
            if !(0x10000..=0x10FFFF).contains(&cp) {
                return None;
            }
            (cp, 4)
        } else {
            return None;
        };

        if cp <= 0xFFFF {
            if out + 2 > dst.len() {
                return None;
            }
            dst[out..out + 2].copy_from_slice(&(cp as u16).to_le_bytes());
            out += 2;
        } else {
            if out + 4 > dst.len() {
                return None;
            }
            let v = cp - 0x10000;
            let high = 0xD800u16 | ((v >> 10) as u16);
            let low = 0xDC00u16 | ((v & 0x3FF) as u16);
            dst[out..out + 2].copy_from_slice(&high.to_le_bytes());
            dst[out + 2..out + 4].copy_from_slice(&low.to_le_bytes());
            out += 4;
        }
        i += used;
    }
    Some(out)
}

unsafe fn pack_nt_object_path(msg: &mut TronaMsg, path: *const u8, path_len: usize) -> Result<u64> {
    if path.is_null() || path_len == 0 {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
    }
    let total = msg.regs.len() * core::mem::size_of::<u64>();
    let bytes = unsafe { core::slice::from_raw_parts_mut(msg.regs.as_mut_ptr() as *mut u8, total) };
    bytes.fill(0);

    let Some(utf16_len) =
        (unsafe { utf8_to_utf16le(path, path_len, &mut bytes[NT_OPEN_PATH_BYTE_OFF..]) })
    else {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
    };
    if utf16_len == 0 || utf16_len > u16::MAX as usize {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
    }
    let end = NT_OPEN_PATH_BYTE_OFF + utf16_len;
    if end > total {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
    }

    if !write_u32(bytes, NT_OPEN_OA_BYTE_OFF, NT_OBJECT_ATTRIBUTES_LEN)
        || !write_u64(bytes, NT_OPEN_OA_BYTE_OFF + 8, 0)
        || !write_u32(bytes, NT_OPEN_OA_BYTE_OFF + 16, 0)
        || !write_u32(bytes, NT_OPEN_OA_BYTE_OFF + 20, 0)
        || !write_u16(bytes, NT_OPEN_US_BYTE_OFF, utf16_len as u16)
        || !write_u16(bytes, NT_OPEN_US_BYTE_OFF + 2, utf16_len as u16)
        || !write_u32(bytes, NT_OPEN_US_BYTE_OFF + 4, 0)
    {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
    }

    Ok(((end + 7) / 8) as u64)
}

#[inline]
fn nt_status(reply: &TronaMsg) -> u32 {
    (reply.regs[0] & 0xFFFF_FFFF) as u32
}

#[inline]
fn nt_information(reply: &TronaMsg) -> u64 {
    reply.regs[1]
}

/// Open a VFS path with raw VFS open flags and mode.
///
/// # Safety
/// `path` must be a readable NUL-terminated byte string.
pub unsafe fn open(path: *const u8, flags: i32, mode: u32) -> Result<i32> {
    unsafe {
        let vfs = crate::client::caps::vfs_ep();
        if vfs.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS public open wire (`fileops/open.rs::handle`):
        //   regs[0] = anchor_fd (-100 == AT_FDCWD)
        //   regs[1] = flags
        //   regs[2] = mode (only consulted with `O_CREAT`)
        //   regs[3] = path_len
        //   regs[4..] = path bytes packed 8 per word
        msg.label = VFS_OPEN;
        msg.regs[0] = (-100i32) as u32 as u64;
        msg.regs[1] = flags as u32 as u64;
        msg.regs[2] = mode as u64;
        let path_len = pack_path(&raw mut msg, 3, path, 128);
        msg.length = 4 + ((path_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            vfs.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != trona_protocol::common::TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0] as i32)
    }
}

/// Open a VFS path read-only.
///
/// # Safety
/// `path` must be a readable NUL-terminated byte string.
pub unsafe fn open_readonly(path: *const u8) -> Result<i32> {
    unsafe { open(path, OPEN_READONLY, 0) }
}

/// Sticky per-process receive slot for the exec MemoryObject cap. Allocated
/// once; the cap that lands in it is forwarded out (to init) on the same exec,
/// so the slot is recycled rather than freed — mirror of the file-backed mmap
/// backing-MO receive slot.
static mut EXEC_MO_RECV_SLOT: u64 = 0;

unsafe fn exec_mo_recv_slot() -> Result<u64> {
    unsafe {
        let slot = *(&raw const EXEC_MO_RECV_SLOT);
        if slot != 0 {
            return Ok(slot);
        }
        let Some(new_slot) = crate::core::slot_alloc::slot_alloc() else {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as u64);
        };
        *(&raw mut EXEC_MO_RECV_SLOT) = new_slot;
        Ok(new_slot)
    }
}

/// Delete whatever sits in the exec-MO receive slot, rearming it empty.
pub fn clear_exec_mo_recv_slot(slot: u64) {
    let depth = crate::core::slot_alloc::slot_invoke_depth(slot);
    let _ = trona_kernel::invoke::cnode_delete_depth(
        trona_kernel::core_types::CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
        slot,
        depth,
    );
}

/// Open `path` for execution and receive a non-exec backing MemoryObject for
/// the binary, resolved under the caller's own VFS authority. Returns the
/// receive-slot address holding the backing MO cap plus the exact file size and
/// file offset within that backing; the caller forwards all three to init on
/// the same exec and then rearms via [`clear_exec_mo_recv_slot`] if exec fails
/// before replacement.
///
/// # Safety
/// `path` must be a readable NUL-terminated byte string.
pub unsafe fn open_for_exec(path: *const u8) -> Result<(u64, u64, u64)> {
    unsafe {
        let vfs = crate::client::caps::vfs_ep();
        if vfs.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS_OPEN_FOR_EXEC wire (exec_helpers::handle_open_for_exec):
        //   regs[0]   = anchor_fd (-100 == AT_FDCWD)
        //   regs[1]   = path_len
        //   regs[2..] = path bytes packed 8 per word
        // Reply: regs[0]=size, regs[1]=image byte offset within the backing MO;
        // caps[0]=non-exec backing MO.
        msg.label = trona_protocol::vfs::public::VFS_OPEN_FOR_EXEC;
        msg.regs[0] = (-100i32) as u32 as u64;
        let path_len = pack_path(&raw mut msg, 1, path, 128);
        msg.length = 2 + ((path_len as u64 + 7) / 8);

        // Arm the sticky receive slot so the reply's MO cap lands there.
        let mo_slot = exec_mo_recv_slot()?;
        clear_exec_mo_recv_slot(mo_slot);
        let saved = trona_kernel::ipc::get_receive_slot_path_ctx(crate::current_ipc_ctx());
        crate::core::ipc_ext::set_receive_slot_ctx(
            crate::current_ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            mo_slot,
            0,
        );

        trona_kernel::ipc::clear_send_caps_ctx(crate::current_ipc_ctx());
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            vfs.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        trona_kernel::ipc::set_receive_slot_path_ctx(
            crate::current_ipc_ctx(),
            saved.0,
            saved.1,
            saved.2,
            saved.3,
        );
        if err != 0 {
            clear_exec_mo_recv_slot(mo_slot);
            return Err(call_error(err));
        }
        if reply.label != trona_protocol::common::TRONA_OK {
            clear_exec_mo_recv_slot(mo_slot);
            return Err(reply.label);
        }
        if reply.length < 2 || reply.regs[0] == 0 {
            clear_exec_mo_recv_slot(mo_slot);
            return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
        }
        Ok((mo_slot, reply.regs[0], reply.regs[1]))
    }
}

/// Read bytes from a VFS file descriptor.
///
/// Returns a short successful count when an error occurs after some bytes
/// have already been copied, matching read-style semantics.
///
/// # Safety
/// `buf` must be writable for `count` bytes.
pub unsafe fn read(fd: i32, buf: *mut u8, count: u64) -> Result<u64> {
    unsafe {
        let vfs = crate::client::caps::vfs_ep();
        if vfs.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut total = 0u64;
        while total < count {
            let chunk = (count - total).min(152);
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            // VFS public read wire (`fileops/read.rs::handle`):
            //   regs[0] = fd
            //   regs[1] = file_offset (u64::MAX == use current offset)
            //   regs[2] = count
            //   regs[3] = flags (0 == inline; VFS_RW_FLAG_SHM for bulk)
            msg.label = VFS_READ;
            msg.length = 4;
            msg.regs[0] = fd as u64;
            msg.regs[1] = u64::MAX;
            msg.regs[2] = chunk;
            msg.regs[3] = 0;

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::current_ipc_ctx(),
                vfs.addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 || reply.label != trona_protocol::common::TRONA_OK {
                return if total > 0 {
                    Ok(total)
                } else if err != 0 {
                    Err(call_error(err))
                } else {
                    Err(reply.label)
                };
            }

            let actual = reply.regs[0];
            if actual == 0 {
                break;
            }

            let src = &reply.regs[1] as *const u64 as *const u8;
            for i in 0..actual as usize {
                if total as usize + i < count as usize {
                    *buf.add(total as usize + i) = *src.add(i);
                }
            }

            total += actual;
            if actual < chunk {
                break;
            }
        }
        Ok(total)
    }
}

/// Reposition a VFS file descriptor.
///
/// # Safety
/// `fd` must name a file descriptor that is valid for the current process.
pub unsafe fn lseek(fd: i32, offset: i64, whence: i32) -> Result<i64> {
    unsafe {
        let vfs = crate::client::caps::vfs_ep();
        if vfs.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_SEEK;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = offset as u64;
        msg.regs[2] = whence as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            vfs.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != trona_protocol::common::TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0] as i64)
    }
}

/// Close a VFS file descriptor.
///
/// # Safety
/// `fd` must name a file descriptor that is valid for the current process.
pub unsafe fn close(fd: i32) -> Result<()> {
    unsafe {
        let vfs = crate::client::caps::vfs_ep();
        if vfs.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            vfs.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != trona_protocol::common::TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

/// Open an existing file through the VFS Win32/NT personality.
///
/// # Safety
/// `path` must point to `path_len` bytes of readable UTF-8.
pub unsafe fn nt_open_existing_readonly(path: *const u8, path_len: usize) -> Result<i32> {
    unsafe {
        let vfs = crate::client::caps::vfs_ep();
        if vfs.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = WIN32_NT_OPEN_FILE;
        msg.length = pack_nt_object_path(&mut msg, path, path_len)?;
        msg.regs[0] = (NT_FILE_READ_DATA | NT_FILE_READ_ATTRIBUTES) as u64
            | ((NT_FILE_SHARE_READ as u64) << 32);
        msg.regs[1] = 0;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            vfs.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK || nt_status(&reply) != 0 {
            return Err(reply.label);
        }
        Ok(reply.regs[2] as i32)
    }
}

/// Read from a VFS fd at an explicit offset through `NtReadFile`.
///
/// # Safety
/// `buf` must be writable for `count` bytes.
pub unsafe fn nt_read_at(fd: i32, offset: u64, buf: *mut u8, count: u64) -> Result<u64> {
    unsafe {
        let vfs = crate::client::caps::vfs_ep();
        if vfs.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut total = 0u64;
        while total < count {
            let chunk = (count - total).min(NT_INLINE_READ_MAX);
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = WIN32_NT_READ_FILE;
            msg.length = 3;
            msg.regs[0] = (fd as u32 as u64) | (chunk << 32);
            msg.regs[1] = offset + total;
            msg.regs[2] = 0;

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::current_ipc_ctx(),
                vfs.addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 || reply.label != TRONA_OK || nt_status(&reply) != 0 {
                return if total > 0 {
                    Ok(total)
                } else if err != 0 {
                    Err(call_error(err))
                } else {
                    Err(reply.label)
                };
            }

            let actual = nt_information(&reply);
            if actual == 0 {
                break;
            }
            let actual = actual.min(chunk);
            let src = &reply.regs[2] as *const u64 as *const u8;
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

/// Read exactly `count` bytes from a VFS fd at an explicit offset through `NtReadFile`.
///
/// # Safety
/// `buf` must be writable for `count` bytes.
pub unsafe fn nt_read_exact_at(fd: i32, offset: u64, buf: *mut u8, count: u64) -> Result<()> {
    let n = unsafe { nt_read_at(fd, offset, buf, count)? };
    if n == count {
        Ok(())
    } else {
        Err(uapi::KERNITE_ERR_OUT_OF_RANGE as u64)
    }
}

/// Close a VFS fd through the VFS Win32/NT personality.
pub unsafe fn nt_close(fd: i32) -> Result<()> {
    unsafe {
        let vfs = crate::client::caps::vfs_ep();
        if vfs.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = WIN32_NT_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u32 as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            vfs.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK || nt_status(&reply) != 0 {
            return Err(reply.label);
        }
        Ok(())
    }
}
