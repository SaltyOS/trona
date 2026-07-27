// SPDX-License-Identifier: GPL-2.0-only
//! POSIX file operations (open, read, write, close, stat, lseek, access, unlink).

use super::pack_path;
use crate::types::*;
use crate::*;
use trona_kernel::core_types::*;
use trona_protocol::posix::*;
use trona_protocol::vfs::public::VFS_WRITE;

/// Open a file at `path` with the given `flags` (O_RDONLY, O_CREAT, etc.).
/// `mode` specifies permission bits when creating a file (masked with 0o777).
///
/// Returns the new file descriptor on success, or -1 on error.
pub unsafe fn posix_open(path: *const u8, flags: i32, mode: u32) -> i32 {
    unsafe {
        let mode = mode & !super::misc::get_umask();
        match trona_runtime::client::vfs::open(path, flags, mode) {
            Ok(fd) => fd,
            Err(label) => super::trona_err_to_posix(label),
        }
    }
}

/// Read up to `count` bytes from file descriptor `fd` into `buf`.
///
/// For reads larger than 4KB, attempts the SHM bulk path first (256KB per
/// IPC round-trip). Falls back to the legacy 152-byte-per-IPC loop if bulk
/// setup fails or the fd type is not bulk-capable.
/// Returns the total bytes read, or -1 on error.
pub unsafe fn posix_read(fd: i32, buf: *mut u8, count: u64) -> i64 {
    unsafe {
        // Use bulk SHM for large reads (> 4KB threshold)
        if count > 4096 {
            if let Some(n) = super::bulk::bulk_read(fd, buf, count) {
                return n as i64;
            }
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[POSIXDBG] read bulk fallback fd=");
                if fd < 0 {
                    _lb.str(b"-");
                    _lb.dec(fd.wrapping_neg() as u64);
                } else {
                    _lb.dec(fd as u64);
                }
                _lb.str(b" count=");
                _lb.dec(count);
                _lb.str(b"\n");
            });
            // SHM not available or setup failed — fall through to legacy
        }

        loop {
            match trona_runtime::client::vfs::read(fd, buf, count) {
                Ok(n) => return n as i64,
                Err(label)
                    if label == uapi::KERNITE_ERR_INTERRUPTED as u64
                        && *(&raw const crate::__sig_last_restart) =>
                {
                    continue;
                }
                Err(label) => {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[POSIXDBG] read legacy err fd=");
                        if fd < 0 {
                            _lb.str(b"-");
                            _lb.dec(fd.wrapping_neg() as u64);
                        } else {
                            _lb.dec(fd as u64);
                        }
                        _lb.str(b" count=");
                        _lb.dec(count);
                        _lb.str(b" label=");
                        _lb.hex(label);
                        _lb.str(b"\n");
                    });
                    return super::trona_err_to_posix(label) as i64;
                }
            }
        }
    }
}

/// Write up to `count` bytes from `buf` to file descriptor `fd`.
///
/// Performs chunked IPC writes (max 144 bytes per round-trip) in a loop.
/// Returns the total bytes written, or -1 on error.
pub unsafe fn posix_write(fd: i32, buf: *const u8, count: u64) -> i64 {
    unsafe {
        let mut total: u64 = 0;

        while total < count {
            let mut chunk = count - total;
            if chunk > 144 {
                chunk = 144;
            }

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            // VFS public write wire (`fileops/write.rs::handle`):
            //   regs[0] = fd
            //   regs[1] = file_offset (u64::MAX == use current offset)
            //   regs[2] = count
            //   regs[3] = flags (0 == inline)
            //   regs[4..] = data packed 8 bytes per word
            msg.label = VFS_WRITE;
            msg.length = 4 + ((chunk + 7) / 8);
            msg.regs[0] = fd as u64;
            msg.regs[1] = u64::MAX;
            msg.regs[2] = chunk;
            msg.regs[3] = 0;

            let dst = &mut msg.regs[4] as *mut u64 as *mut u8;
            for i in 0..chunk as usize {
                *dst.add(i) = *buf.add(total as usize + i);
            }

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                trona_runtime::client::caps::vfs_ep().addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
                if err == (uapi::KERNITE_ERR_INTERRUPTED as u64) as i32 {
                    if total > 0 {
                        return total as i64;
                    }
                    if *(&raw const crate::__sig_last_restart) {
                        continue;
                    }
                    return -4; // EINTR
                }
                if total > 0 {
                    return total as i64;
                }
                return if err != 0 {
                    super::call_err_to_posix_i64(err)
                } else {
                    super::trona_err_to_posix(reply.label) as i64
                };
            }

            let actual = reply.regs[0];
            total += actual;
            if actual < chunk {
                break;
            }
        }

        total as i64
    }
}

/// Read up to `count` bytes from `fd` at `offset` without changing the file offset.
///
/// Uses a dedicated VFS PREAD protocol so the server handles the offset
/// atomically without touching the fd cursor.
/// Returns the number of bytes read, or a negative errno on error.
pub unsafe fn posix_pread(fd: i32, buf: *mut u8, count: u64, offset: i64) -> i64 {
    if offset < 0 {
        return -22; // EINVAL
    }
    unsafe {
        let mut total: u64 = 0;

        while total < count {
            let mut chunk = count - total;
            if chunk > 152 {
                chunk = 152;
            }

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            // VFS public read wire (`fileops/read.rs::handle`):
            //   regs[0] = fd
            //   regs[1] = file_offset
            //   regs[2] = count
            //   regs[3] = flags (0 == inline; VFS_RW_FLAG_SHM for bulk)
            msg.label = VFS_PREAD;
            msg.length = 4;
            msg.regs[0] = fd as u64;
            let cur_off = match (offset as u64).checked_add(total) {
                Some(v) => v,
                None => return if total > 0 { total as i64 } else { -22 }, // EINVAL
            };
            msg.regs[1] = cur_off;
            msg.regs[2] = chunk;
            msg.regs[3] = 0;

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                trona_runtime::client::caps::vfs_ep().addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
                if total > 0 {
                    return total as i64;
                }
                return if err != 0 {
                    super::call_err_to_posix_i64(err)
                } else {
                    super::trona_err_to_posix(reply.label) as i64
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

        total as i64
    }
}

/// Write up to `count` bytes to `fd` at `offset` without changing the file offset.
///
/// Uses a dedicated VFS PWRITE protocol so the server handles the offset
/// atomically without touching the fd cursor. Large writes attempt the bulk
/// SHM path first and fall back to inline IPC when unavailable.
/// Returns the number of bytes written, or a negative errno on error.
pub unsafe fn posix_pwrite(fd: i32, buf: *const u8, count: u64, offset: i64) -> i64 {
    if offset < 0 {
        return -22; // EINVAL
    }
    unsafe {
        if count > 4096 {
            if let Some(n) = super::bulk::bulk_pwrite(fd, buf, count, offset as u64) {
                return n as i64;
            }
        }

        let mut total: u64 = 0;

        while total < count {
            let mut chunk = count - total;
            if chunk > 136 {
                chunk = 136;
            }

            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            // VFS public write wire (`fileops/write.rs::handle`):
            //   regs[0] = fd
            //   regs[1] = file_offset (explicit pwrite offset)
            //   regs[2] = count
            //   regs[3] = flags (0 == inline)
            //   regs[4..] = data packed 8 bytes per word
            msg.label = VFS_PWRITE;
            msg.length = 4 + ((chunk + 7) / 8);
            msg.regs[0] = fd as u64;
            let cur_off = match (offset as u64).checked_add(total) {
                Some(v) => v,
                None => return if total > 0 { total as i64 } else { -22 }, // EINVAL
            };
            msg.regs[1] = cur_off;
            msg.regs[2] = chunk;
            msg.regs[3] = 0;

            let dst = &mut msg.regs[4] as *mut u64 as *mut u8;
            for i in 0..chunk as usize {
                *dst.add(i) = *buf.add(total as usize + i);
            }

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                trona_runtime::client::caps::vfs_ep().addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
                if total > 0 {
                    return total as i64;
                }
                return if err != 0 {
                    super::call_err_to_posix_i64(err)
                } else {
                    super::trona_err_to_posix(reply.label) as i64
                };
            }

            let actual = reply.regs[0];
            total += actual;
            if actual < chunk {
                break;
            }
        }

        total as i64
    }
}

/// Close a file descriptor. Returns 0 on success, -1 on error.
pub unsafe fn posix_close(fd: i32) -> i32 {
    unsafe {
        match trona_runtime::client::vfs::close(fd) {
            Ok(()) => 0,
            Err(label) => super::trona_err_to_posix(label),
        }
    }
}

/// Get file status by path. Populates `*st` with inode, mode, size, etc.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_stat(path: *const u8, st: *mut TronaStat) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS_STAT path wire:
        //   regs[0] = path_len
        //   regs[1..] = path bytes packed 8 per word
        msg.label = VFS_POSIX_STAT;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }

        if !st.is_null() {
            (*st).st_ino = reply.regs[0];
            (*st).st_mode = reply.regs[1];
            (*st).st_nlink = reply.regs[2];
            (*st).st_size = reply.regs[3];
            (*st).st_uid = reply.regs[4];
            (*st).st_gid = reply.regs[5];
            (*st).st_mtime = reply.regs[6];
            (*st).st_type = reply.regs[7];
        }
        0
    }
}

/// Get file status by path (symlink-aware). Currently identical to `posix_stat`.
pub unsafe fn posix_lstat(path: *const u8, st: *mut TronaStat) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS_LSTAT uses the same compact path wire as VFS_STAT.
        msg.label = VFS_POSIX_LSTAT;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }

        if !st.is_null() {
            (*st).st_ino = reply.regs[0];
            (*st).st_mode = reply.regs[1];
            (*st).st_nlink = reply.regs[2];
            (*st).st_size = reply.regs[3];
            (*st).st_uid = reply.regs[4];
            (*st).st_gid = reply.regs[5];
            (*st).st_mtime = reply.regs[6];
            (*st).st_type = reply.regs[7];
        }
        0
    }
}

/// Get file status by open file descriptor. Returns 0 on success, -1 on error.
pub unsafe fn posix_fstat(fd: i32, st: *mut TronaStat) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FSTAT;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }

        if !st.is_null() {
            (*st).st_ino = reply.regs[0];
            (*st).st_mode = reply.regs[1];
            (*st).st_nlink = reply.regs[2];
            (*st).st_size = reply.regs[3];
            (*st).st_uid = reply.regs[4];
            (*st).st_gid = reply.regs[5];
            (*st).st_mtime = reply.regs[6];
            (*st).st_type = reply.regs[7];
        }
        0
    }
}

/// Reposition the file offset of `fd`. `whence` is SEEK_SET/CUR/END.
/// Returns the new offset on success, -1 on error.
pub unsafe fn posix_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe {
        match trona_runtime::client::vfs::lseek(fd, offset, whence) {
            Ok(offset) => offset,
            Err(label) => super::trona_err_to_posix(label) as i64,
        }
    }
}

/// Check file accessibility. `mode` is a bitmask of R_OK/W_OK/X_OK/F_OK.
/// Returns 0 if access is permitted, -1 on error.
pub unsafe fn posix_access(path: *const u8, mode: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS public access wire (`fileops/access.rs::handle`):
        //   regs[0] = anchor_fd (i32, -100 == AT_FDCWD)
        //   regs[1] = mode (R_OK | W_OK | X_OK | F_OK)
        //   regs[2] = at_flags (0 == follow final symlink)
        //   regs[3] = path_len
        //   regs[4..] = path bytes packed 8 per word
        msg.label = VFS_POSIX_ACCESS;
        msg.regs[0] = (-100i32) as u32 as u64;
        msg.regs[1] = mode as u64;
        msg.regs[2] = 0;
        let path_len = pack_path(&raw mut msg, 3, path, 128);
        msg.length = 4 + ((path_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Remove (unlink) a file by path. Returns 0 on success, -1 on error.
pub unsafe fn posix_unlink(path: *const u8) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS public unlink wire (`fileops/unlink.rs::handle`):
        //   regs[0] = anchor_fd (i32, -100 == AT_FDCWD)
        //   regs[1] = at_flags (AT_REMOVEDIR is routed via VFS_RMDIR)
        //   regs[2] = path_len
        //   regs[3..] = path bytes packed 8 per word
        msg.label = VFS_POSIX_UNLINK;
        msg.regs[0] = (-100i32) as u32 as u64;
        msg.regs[1] = 0;
        let path_len = pack_path(&raw mut msg, 2, path, 128);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Rename a file from `old_path` to `new_path`.
///
/// Both paths are packed into message registers (old_len, new_len, then
/// path bytes). Returns 0 on success, -1 on error.
pub unsafe fn posix_rename(old_path: *const u8, new_path: *const u8) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_RENAME;

        let mut old_len: u8 = 0;
        while *old_path.add(old_len as usize) != 0 && old_len < 64 {
            old_len += 1;
        }
        let mut new_len: u8 = 0;
        while *new_path.add(new_len as usize) != 0 && new_len < 64 {
            new_len += 1;
        }

        // VFS public rename wire (`fileops/rename.rs::handle`):
        //   regs[0] = anchor_fd_old (i32, -100 == AT_FDCWD)
        //   regs[1] = anchor_fd_new (i32, -100 == AT_FDCWD)
        //   regs[2] = old_path_len
        //   regs[3] = new_path_len
        //   regs[4..] = old_path bytes, then new_path bytes packed
        msg.regs[0] = (-100i32) as u32 as u64;
        msg.regs[1] = (-100i32) as u32 as u64;
        msg.regs[2] = old_len as u64;
        msg.regs[3] = new_len as u64;
        for i in 4..20 {
            msg.regs[i] = 0;
        }
        let dst = &mut msg.regs[4] as *mut u64 as *mut u8;
        for i in 0..old_len as usize {
            *dst.add(i) = *old_path.add(i);
        }
        let dst2 = (&mut msg.regs[4 + ((old_len as usize + 7) / 8)]) as *mut u64 as *mut u8;
        for i in 0..new_len as usize {
            *dst2.add(i) = *new_path.add(i);
        }
        msg.length = 4 + ((old_len as u64 + 7) / 8) + ((new_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Create a directory at `path` with permissions `mode`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_mkdir(path: *const u8, mode: i32) -> i32 {
    unsafe {
        let mode = (mode as u32) & !super::misc::get_umask();
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS public mkdir wire (`fileops/mkdir.rs::handle`):
        //   regs[0] = anchor_fd (i32, -100 == AT_FDCWD)
        //   regs[1] = mode
        //   regs[2] = path_len
        //   regs[3..] = path bytes packed 8 per word
        msg.label = VFS_POSIX_MKDIR;
        msg.regs[0] = (-100i32) as u32 as u64;
        msg.regs[1] = mode as u64;
        let path_len = pack_path(&raw mut msg, 2, path, 128);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Remove an empty directory. Returns 0 on success, -1 on error.
pub unsafe fn posix_rmdir(path: *const u8) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS public rmdir wire (`personality/posix/unlink.rs::dispatch_path_unlink`):
        //   regs[0] = anchor_fd (i32, -100 == AT_FDCWD)
        //   regs[1] = flags (unused)
        //   regs[2] = path_len
        //   regs[3..] = path bytes packed 8 per word
        msg.label = VFS_POSIX_RMDIR;
        msg.regs[0] = (-100i32) as u32 as u64;
        msg.regs[1] = 0;
        let path_len = pack_path(&raw mut msg, 2, path, 128);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Open a directory for iteration. Returns a directory fd on success, -1 on error.
pub unsafe fn posix_opendir(path: *const u8) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // `opendir(path)` reduces to `open(path, O_DIRECTORY |
        // O_RDONLY)` against the VFS public open wire. The
        // `VFS_POSIX_OPENDIR` const aliases `VFS_OPEN`, so the
        // dispatch path matches the regular open handler.
        // VFS public open wire (`fileops/open.rs::handle`):
        //   regs[0] = anchor_fd (-100 == AT_FDCWD)
        //   regs[1] = flags (O_DIRECTORY | O_RDONLY)
        //   regs[2] = mode (unused without O_CREAT)
        //   regs[3] = path_len
        //   regs[4..] = path bytes
        const O_RDONLY: u64 = 0;
        const O_DIRECTORY: u64 = 0x10000;
        msg.label = VFS_POSIX_OPENDIR;
        msg.regs[0] = (-100i32) as u32 as u64;
        msg.regs[1] = O_DIRECTORY | O_RDONLY;
        msg.regs[2] = 0;
        let path_len = pack_path(&raw mut msg, 3, path, 128);
        msg.length = 4 + ((path_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Read the next directory entry from `dir_fd` into `*entry`.
///
/// Returns 1 if an entry was read, 0 at end-of-directory or on error.
/// The entry name is unpacked from the VFS readdir reply envelope
/// and null-terminated.
pub unsafe fn posix_readdir(dir_fd: i32, entry: *mut TronaDirent) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_READDIR;
        msg.length = 2;
        msg.regs[0] = dir_fd as u64;
        msg.regs[1] = 0;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != (uapi::KERNITE_OK as u64) {
            return 0;
        }

        let entries = reply.regs[1] as u32;
        if entries == 0 {
            return 0;
        }

        let name_len = reply.regs[5] as u8;
        if name_len == 0 {
            return 0;
        }
        if !entry.is_null() {
            (*entry).d_namlen = name_len;
            (*entry).d_ino = reply.regs[3];
            (*entry).d_type = reply.regs[4] as u8;
            let src = &reply.regs[6] as *const u64 as *const u8;
            let max_copy = if name_len < 127 { name_len } else { 127 };
            for i in 0..max_copy as usize {
                (*entry).d_name[i] = *src.add(i);
            }
            (*entry).d_name[max_copy as usize] = 0;
        }
        1
    }
}

/// Read one extended attribute from an open fd.
///
/// Returns the total attribute length on success; copies up to `size`
/// bytes into `value` when `value` is non-null.
pub unsafe fn posix_fgetxattr(fd: i32, name: *const u8, value: *mut u8, size: usize) -> i64 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FGETXATTR;
        msg.regs[0] = fd as u64;
        msg.regs[1] = size as u64;
        let name_len = pack_path(&raw mut msg, 2, name, 128);
        if name_len == 0 {
            return -22;
        }
        msg.length = 3 + ((name_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix_i64(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label) as i64;
        }
        let total_len = reply.regs[0] as usize;
        let copy_len = (reply.regs[1] as usize).min(size);
        if !value.is_null() && copy_len > 0 {
            let src = &reply.regs[2] as *const u64 as *const u8;
            for i in 0..copy_len {
                *value.add(i) = *src.add(i);
            }
        }
        total_len as i64
    }
}

/// List extended-attribute names for an open fd.
pub unsafe fn posix_flistxattr(fd: i32, list: *mut u8, size: usize) -> i64 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FLISTXATTR;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = size as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix_i64(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label) as i64;
        }
        let total_len = reply.regs[0] as usize;
        let copy_len = (reply.regs[1] as usize).min(size);
        if !list.is_null() && copy_len > 0 {
            let src = &reply.regs[2] as *const u64 as *const u8;
            for i in 0..copy_len {
                *list.add(i) = *src.add(i);
            }
        }
        total_len as i64
    }
}

/// Set one extended attribute on an open fd.
pub unsafe fn posix_fsetxattr(
    fd: i32,
    name: *const u8,
    value: *const u8,
    size: usize,
    flags: u32,
) -> i32 {
    unsafe {
        let name_len = cstr_len_bounded(name, 128);
        if name_len == 0 || size > 128 {
            return -22;
        }
        let name_words = words_for_len(name_len);
        let value_reg = 4 + name_words;
        if value_reg + words_for_len(size) > 32 {
            return -22;
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FSETXATTR;
        msg.regs[0] = fd as u64;
        msg.regs[1] = flags as u64;
        msg.regs[2] = name_len as u64;
        msg.regs[3] = size as u64;
        pack_bytes_at(&mut msg, 4, name, name_len);
        pack_bytes_at(&mut msg, value_reg, value, size);
        msg.length = (value_reg + words_for_len(size)) as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Remove one extended attribute from an open fd.
pub unsafe fn posix_fremovexattr(fd: i32, name: *const u8) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FREMOVEXATTR;
        msg.regs[0] = fd as u64;
        let name_len = pack_path(&raw mut msg, 1, name, 128);
        if name_len == 0 {
            return -22;
        }
        msg.length = 2 + ((name_len as u64 + 7) / 8);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

unsafe fn cstr_len_bounded(ptr: *const u8, max: usize) -> usize {
    unsafe {
        if ptr.is_null() {
            return 0;
        }
        let mut len = 0usize;
        while len < max {
            if *ptr.add(len) == 0 {
                return len;
            }
            len += 1;
        }
        0
    }
}

unsafe fn pack_bytes_at(msg: &mut TronaMsg, reg_start: usize, src: *const u8, len: usize) {
    unsafe {
        if len == 0 || src.is_null() {
            return;
        }
        let dst = (&raw mut msg.regs[reg_start]) as *mut u64 as *mut u8;
        for i in 0..len {
            *dst.add(i) = *src.add(i);
        }
    }
}

#[inline]
fn words_for_len(len: usize) -> usize {
    (len + 7) / 8
}

/// Close a directory fd. Delegates to `posix_close`.
pub unsafe fn posix_closedir(dir_fd: i32) -> i32 {
    unsafe { posix_close(dir_fd) }
}

/// Truncate file `fd` to `length` bytes. Returns 0 on success, -1 on error.
pub unsafe fn posix_ftruncate(fd: i32, length: u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FTRUNCATE;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = length;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Create a symbolic link at `linkpath` pointing to `target`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_symlink(target: *const u8, linkpath: *const u8) -> i32 {
    unsafe { super::at::posix_symlinkat(target, -100, linkpath) }
}

/// Read the target of a symbolic link at `path`.
/// Returns the number of bytes placed in `buf`, or -1 on error.
pub unsafe fn posix_readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> i64 {
    unsafe { super::at::posix_readlinkat(-100, path, buf, bufsiz) }
}

/// Sync a file descriptor's data to persistent storage.
/// Returns 0 on success, negative errno on error.
pub unsafe fn posix_fsync(fd: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_FSYNC;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Create a hard link: `newpath` becomes an additional name for `oldpath`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_link(oldpath: *const u8, newpath: *const u8) -> i32 {
    unsafe { super::at::posix_linkat(-100, oldpath, -100, newpath, 0) }
}

unsafe fn read_statvfs_reply(reply: &TronaMsg, st: *mut TronaStatvfs) {
    if st.is_null() {
        return;
    }
    unsafe {
        (*st).f_bsize = reply.regs[0];
        (*st).f_frsize = reply.regs[1];
        (*st).f_blocks = reply.regs[2];
        (*st).f_bfree = reply.regs[3];
        (*st).f_bavail = reply.regs[4];
        (*st).f_files = reply.regs[5];
        (*st).f_ffree = reply.regs[6];
        (*st).f_favail = reply.regs[7];
        (*st).f_fsid = reply.regs[8];
        (*st).f_flag = reply.regs[9];
        (*st).f_namemax = reply.regs[10];
    }
}

/// POSIX `statvfs(path)`. Populates `*st` with mount-wide block / inode
/// counts. The vfs server's `VFS_STATVFS` wire is fd-based, so this
/// shim opens the path read-only, dispatches the statvfs, and closes
/// the fd. Returns 0 on success, -errno on error.
pub unsafe fn posix_statvfs(path: *const u8, st: *mut TronaStatvfs) -> i32 {
    const O_RDONLY: i32 = 0;
    let fd = unsafe { posix_open(path, O_RDONLY, 0) };
    if fd < 0 {
        return fd;
    }
    let result = unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_STATFS;
        msg.regs[0] = fd as u32 as u64;
        msg.length = 1;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            super::call_err_to_posix(err)
        } else if reply.label != (uapi::KERNITE_OK as u64) {
            super::trona_err_to_posix(reply.label)
        } else {
            read_statvfs_reply(&reply, st);
            0
        }
    };
    let _ = unsafe { posix_close(fd) };
    result
}

/// MountKind u8 values (mirror of `vfs_core::mount::MountKind` in
/// `userland/core/vfs/src/vfs_core/mount.rs`):
///   Empty=0, Initrd=1, Ramfs=2, Tmpfs=3, Devfs=4, Procfs=5,
///   Sysctlfs=6, Pipefs=7, SaltyFs=8, Inet=9, Pty=10, Fb=11.
fn mount_kind_for_fstype(fstype: &[u8]) -> Option<u8> {
    match fstype {
        b"initrd" => Some(1),
        b"ramfs" => Some(2),
        b"tmpfs" => Some(3),
        b"devfs" => Some(4),
        b"procfs" => Some(5),
        b"sysctlfs" => Some(6),
        b"pipefs" => Some(7),
        b"saltyfs" => Some(8),
        b"inet" => Some(9),
        b"pty" => Some(10),
        b"fb" => Some(11),
        _ => None,
    }
}

fn apply_mount_option(flags: &mut u64, opt: &[u8]) {
    let mut start = 0usize;
    let mut end = opt.len();
    while start < end && (opt[start] == b' ' || opt[start] == b'\t') {
        start += 1;
    }
    while end > start && (opt[end - 1] == b' ' || opt[end - 1] == b'\t') {
        end -= 1;
    }
    match &opt[start..end] {
        b"" | b"defaults" => {}
        b"casefold" | b"nocase" => *flags |= VFS_MOUNT_FLAG_CASEFOLD,
        b"case" | b"case-sensitive" => *flags &= !VFS_MOUNT_FLAG_CASEFOLD,
        _ => {}
    }
}

fn mount_flags_with_options(flags: u32, opts: &[u8]) -> u64 {
    let mut out = flags as u64;
    let end = opts.iter().position(|b| *b == 0).unwrap_or(opts.len());
    let opts = &opts[..end];
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= opts.len() {
        if i == opts.len() || opts[i] == b',' {
            apply_mount_option(&mut out, &opts[start..i]);
            start = i.saturating_add(1);
        }
        i += 1;
    }
    out
}

/// Open `target` as a directory and return the resulting fd, or a
/// negative POSIX errno. Used by the mount/umount/statvfs path-based
/// wrappers to convert a path into the fd the vfs server expects.
unsafe fn open_dir_for_fd(target: &[u8]) -> i32 {
    if target.is_empty() || target.len() > 127 {
        return -22; // EINVAL
    }
    let mut buf = [0u8; 128];
    for (i, b) in target.iter().enumerate() {
        buf[i] = *b;
    }
    buf[target.len()] = 0;
    // O_DIRECTORY | O_RDONLY
    const O_RDONLY: i32 = 0;
    const O_DIRECTORY: i32 = 0x10000;
    unsafe { posix_open(buf.as_ptr(), O_DIRECTORY | O_RDONLY, 0) }
}

/// `mount(2)` shim. The vfs server's `VFS_MOUNT` wire is fd-based:
///   regs[0] = target_fd (mount-point directory's fd)
///   regs[1] = mount_kind (u8)
///   regs[2] = source_fd (0 for in-memory backends, daemon ep cap
///             for SaltyFs — currently unsupported here)
///   regs[3] = flags
///
/// This wrapper opens the mount-point as `O_DIRECTORY`, dispatches
/// the mount, and closes the directory fd. Recognised generic options
/// are lowered into stable VFS mount flag bits; backend-specific
/// opaque options still belong on backend-owned ABIs.
pub unsafe fn posix_mount(target: &[u8], fstype: &[u8], flags: u32, opts: &[u8]) -> i32 {
    let kind = match mount_kind_for_fstype(fstype) {
        Some(k) => k,
        None => return -22, // EINVAL — unknown filesystem type
    };
    if kind == 8 {
        // SaltyFs requires a daemon endpoint cap as source; the
        // path-based POSIX wire cannot carry that. Use the dedicated
        // saltyfs mount API instead.
        return -38; // ENOSYS
    }
    let target_fd = unsafe { open_dir_for_fd(target) };
    if target_fd < 0 {
        return target_fd;
    }
    let result = unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_MOUNT;
        msg.regs[0] = target_fd as u32 as u64;
        msg.regs[1] = kind as u64;
        msg.regs[2] = 0;
        msg.regs[3] = mount_flags_with_options(flags, opts);
        // Absolute mount-point path for the server's `f_mntonname`
        // record: regs[4] = length, regs[5..] = bytes (8 per word).
        // Bounded to the stored width; the server truncates further.
        let path_len = target.len().min(TRONA_MOUNT_INFO_PATH_LEN);
        msg.regs[4] = path_len as u64;
        let path_dst = (&raw mut msg.regs[5]) as *mut u8;
        for i in 0..path_len {
            *path_dst.add(i) = target[i];
        }
        msg.length = 5 + (path_len as u64).div_ceil(8);
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            super::call_err_to_posix(err)
        } else if reply.label != (uapi::KERNITE_OK as u64) {
            super::trona_err_to_posix(reply.label)
        } else {
            0
        }
    };
    let _ = unsafe { posix_close(target_fd) };
    result
}

/// `umount(2)` shim. The server rejects forced/lazy semantics today,
/// so `flags` is forwarded as-is for future expansion but the only
/// meaningful value right now is 0.
///
/// Wire (vfs canonical, `fileops/mount.rs::handle_umount`):
///   regs[0] = target_fd (mount-point directory's fd — must reference
///             the mount root, same fd that was passed to `VFS_MOUNT`)
///   regs[1] = flags
pub unsafe fn posix_umount(target: &[u8], flags: u32) -> i32 {
    let target_fd = unsafe { open_dir_for_fd(target) };
    if target_fd < 0 {
        return target_fd;
    }
    let result = unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_UMOUNT;
        msg.regs[0] = target_fd as u32 as u64;
        msg.regs[1] = flags as u64;
        msg.length = 2;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            super::call_err_to_posix(err)
        } else if reply.label != (uapi::KERNITE_OK as u64) {
            super::trona_err_to_posix(reply.label)
        } else {
            0
        }
    };
    let _ = unsafe { posix_close(target_fd) };
    result
}

/// `mount(2)`-style remount shim. The vfs server's `VFS_REMOUNT`
/// wire is fd-based — the caller opens the mount root, dispatches
/// the remount, and closes. Recognised generic options are lowered
/// into the same stable VFS flag bits as `posix_mount`.
///
/// Wire (vfs canonical, `fileops/mount.rs::handle_remount`):
///   regs[0] = target_fd
///   regs[1] = flags
pub unsafe fn posix_remount(target: &[u8], flags: u32, opts: &[u8]) -> i32 {
    let target_fd = unsafe { open_dir_for_fd(target) };
    if target_fd < 0 {
        return target_fd;
    }
    let result = unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_REMOUNT;
        msg.regs[0] = target_fd as u32 as u64;
        msg.regs[1] = mount_flags_with_options(flags, opts);
        msg.length = 2;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            super::call_err_to_posix(err)
        } else if reply.label != (uapi::KERNITE_OK as u64) {
            super::trona_err_to_posix(reply.label)
        } else {
            0
        }
    };
    let _ = unsafe { posix_close(target_fd) };
    result
}

/// BSD `getfsstat` source — `VFS_MOUNT_LIST`. Fills `out` with up to
/// its length of mount records and returns the number written.
///
/// An empty `out` is a count-only call: it returns the total number
/// of active mounts so a caller (e.g. `getmntinfo`) can size its
/// buffer before refilling. Records travel through the per-process
/// bulk SHM region (see [`bulk::bulk_mount_list`]); the legacy
/// IPC-buffer reply path is gone. Returns `-EIO` when the bulk
/// mount-list path is unavailable.
pub unsafe fn posix_mount_list(out: &mut [TronaMountInfo]) -> i32 {
    let count_only = out.is_empty();
    match unsafe { super::bulk::bulk_mount_list(out) } {
        Some((written, available)) => {
            if count_only {
                available
            } else {
                written
            }
        }
        None => -5, // EIO
    }
}

/// POSIX `fstatvfs(fd)`. Same reply layout as [`posix_statvfs`].
pub unsafe fn posix_fstatvfs(fd: i32, st: *mut TronaStatvfs) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_FSTATFS;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = 0;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }
        read_statvfs_reply(&reply, st);
        0
    }
}
