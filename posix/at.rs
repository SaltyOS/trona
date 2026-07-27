// SPDX-License-Identifier: GPL-2.0-only
//! POSIX *at() operations (openat, fstatat, unlinkat, renameat, symlinkat).

use super::pack_path;
use crate::types::*;
use crate::*;
use trona_kernel::core_types::*;
use trona_protocol::posix::*;

/// openat(dirfd, path, flags, mode)
/// IPC: reg[0]=dirfd, reg[1]=open_flags, reg[2]=mode, reg[3..]=path(len+data)
pub unsafe fn posix_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i32 {
    unsafe {
        let mode = mode & !super::misc::get_umask();
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_OPENAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = flags as u32 as u64;
        msg.regs[2] = mode as u64;
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

/// fstatat(dirfd, path, statbuf, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub unsafe fn posix_fstatat(dirfd: i32, path: *const u8, st: *mut TronaStat, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FSTATAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
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

/// unlinkat(dirfd, path, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub unsafe fn posix_unlinkat(dirfd: i32, path: *const u8, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_UNLINKAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
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

/// renameat(old_dirfd, old_path, new_dirfd, new_path)
/// IPC: reg[0]=old_dirfd, reg[1]=new_dirfd, reg[2]=old_len, reg[3]=new_len, reg[4..]=paths
pub unsafe fn posix_renameat(
    old_dirfd: i32,
    old_path: *const u8,
    new_dirfd: i32,
    new_path: *const u8,
) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_RENAMEAT;

        let mut old_len: u8 = 0;
        while *old_path.add(old_len as usize) != 0 && old_len < 64 {
            old_len += 1;
        }
        let mut new_len: u8 = 0;
        while *new_path.add(new_len as usize) != 0 && new_len < 64 {
            new_len += 1;
        }

        let old_regs = (old_len as usize + 7) / 8;
        let new_regs = (new_len as usize + 7) / 8;
        if 4 + old_regs + new_regs > 20 {
            return -36; // ENAMETOOLONG
        }

        msg.regs[0] = old_dirfd as u32 as u64;
        msg.regs[1] = new_dirfd as u32 as u64;
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

/// mkdirat(dirfd, path, mode)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2..]=path(len+data)
pub unsafe fn posix_mkdirat(dirfd: i32, path: *const u8, mode: i32) -> i32 {
    unsafe {
        let mode = (mode as u32) & !super::misc::get_umask();
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_MKDIRAT;
        msg.regs[0] = dirfd as u32 as u64;
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

/// mknodat(dirfd, path, mode, dev)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=dev, reg[3..]=path(len+data)
pub unsafe fn posix_mknodat(dirfd: i32, path: *const u8, mode: u32, dev: u64) -> i32 {
    unsafe {
        let mode = mode & !super::misc::get_umask();
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_MKNOD;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        msg.regs[2] = dev;
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

/// faccessat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
pub unsafe fn posix_faccessat(dirfd: i32, path: *const u8, mode: i32, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FACCESSAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        msg.regs[2] = at_flags as u32 as u64;
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

/// fchmodat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
pub unsafe fn posix_fchmodat(dirfd: i32, path: *const u8, mode: u32, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FCHMODAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        msg.regs[2] = at_flags as u32 as u64;
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

/// fchownat(dirfd, path, uid, gid, flags)
/// IPC: reg[0]=dirfd, reg[1]=uid, reg[2]=gid, reg[3]=at_flags, reg[4..]=path(len+data)
pub unsafe fn posix_fchownat(
    dirfd: i32,
    path: *const u8,
    uid: u32,
    gid: u32,
    at_flags: i32,
) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_FCHOWNAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = uid as u64;
        msg.regs[2] = gid as u64;
        msg.regs[3] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 4, path, 128);
        msg.length = 5 + ((path_len as u64 + 7) / 8);

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

/// utimensat(dirfd, path, times, flags)
/// IPC (vfs canonical): reg[0]=anchor_fd, reg[1]=at_flags,
/// reg[2]=atime_ns, reg[3]=mtime_ns, reg[4]=path_len, reg[5..]=path bytes.
///
/// The vfs side takes a single ns scalar per timestamp rather than the
/// sec+nsec split — collapse the pair here (sec * 1_000_000_000 + nsec).
/// UTIME_OMIT-style sentinels are encoded in `at_flags` by the caller
/// (basaltc) before this call.
pub unsafe fn posix_utimensat(
    dirfd: i32,
    path: *const u8,
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    at_flags: i32,
) -> i32 {
    unsafe {
        let atime_ns = (atime_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(atime_nsec as u64);
        let mtime_ns = (mtime_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(mtime_nsec as u64);
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_UTIMENSAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
        msg.regs[2] = atime_ns;
        msg.regs[3] = mtime_ns;
        let path_len = pack_path(&raw mut msg, 4, path, 128);
        msg.length = 5 + ((path_len as u64 + 7) / 8);

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

/// Create a symbolic link at `linkpath` (relative to `newdirfd`) pointing to `target`.
///
/// IPC layout (vfs canonical, `fileops/symlink.rs`):
///   regs[0] = anchor_fd (newdirfd; AT_FDCWD = -100)
///   regs[1] = mode (POSIX `symlink(2)` itself takes no mode argument —
///             pass 0 here; vfs backend applies the conventional 0o777 default)
///   regs[2] = link_path_len
///   regs[3] = target_len
///   regs[4..4+ceil(link_path_len/8)] = link path bytes
///   regs[4+ceil(link_path_len/8)..] = target bytes
///
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_SYMLINKAT;

        // Measure target length
        let mut target_len: u8 = 0;
        while *target.add(target_len as usize) != 0 && target_len < 64 {
            target_len += 1;
        }

        // Measure link path length
        let mut link_len: u8 = 0;
        while *linkpath.add(link_len as usize) != 0 && link_len < 64 {
            link_len += 1;
        }

        // VFS symlink wire (`personality/posix/symlink.rs::handle`):
        //   regs[0] = anchor_fd
        //   regs[1] = target_len
        //   regs[2] = link_path_len
        //   regs[3..] = target bytes, then link path bytes, 8 per word
        let target_regs = (target_len as usize + 7) / 8;
        let link_regs = (link_len as usize + 7) / 8;
        if 3 + target_regs + link_regs > 20 {
            return -36; // ENAMETOOLONG
        }

        msg.regs[0] = newdirfd as u32 as u64;
        msg.regs[1] = target_len as u64;
        msg.regs[2] = link_len as u64;

        // target bytes at regs[3..]
        let dst_target = &mut msg.regs[3] as *mut u64 as *mut u8;
        for i in 0..target_len as usize {
            *dst_target.add(i) = *target.add(i);
        }

        // link path bytes immediately after target (8-byte aligned)
        let dst_link = (&mut msg.regs[3 + target_regs]) as *mut u64 as *mut u8;
        for i in 0..link_len as usize {
            *dst_link.add(i) = *linkpath.add(i);
        }

        msg.length = (3 + target_regs + link_regs) as u64;

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

/// Read the target of a symbolic link at `path` (relative to `dirfd`).
/// IPC layout: regs[0]=dirfd, regs[1]=path_len, regs[2..]=path bytes
/// Reply: regs[0]=target_len, regs[1..]=target bytes
/// Returns the number of bytes placed in `buf`, or -1 on error.
pub unsafe fn posix_readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, bufsiz: usize) -> i64 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_READLINKAT;
        msg.regs[0] = dirfd as u32 as u64;
        let path_len = pack_path(&raw mut msg, 1, path, 128);
        msg.length = 2 + ((path_len as u64 + 7) / 8);

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

        let target_len = reply.regs[0] as usize;
        let copy_len = if target_len < bufsiz {
            target_len
        } else {
            bufsiz
        };
        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..copy_len {
            *buf.add(i) = *src.add(i);
        }
        copy_len as i64
    }
}

/// Create a hard link: `newpath` (relative to `newdirfd`) becomes an additional
/// name for the file at `oldpath` (relative to `olddirfd`).
///
/// IPC layout (vfs canonical, `fileops/link.rs`):
///   regs[0] = anchor_fd_old (olddirfd)
///   regs[1] = anchor_fd_new (newdirfd)
///   regs[2] = target_path_len (= old_len; existing file to link to)
///   regs[3] = link_path_len (= new_len; new directory entry path)
///   regs[4] = flags (AT_SYMLINK_FOLLOW etc.)
///   regs[5..5+ceil(target_len/8)] = target path bytes (= oldpath)
///   regs[5+ceil(target_len/8)..] = link path bytes (= newpath)
///
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_linkat(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: i32,
) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_LINKAT;

        // Measure old path length (target — existing file)
        let mut old_len: u8 = 0;
        while *oldpath.add(old_len as usize) != 0 && old_len < 64 {
            old_len += 1;
        }

        // Measure new path length (link — new directory entry)
        let mut new_len: u8 = 0;
        while *newpath.add(new_len as usize) != 0 && new_len < 64 {
            new_len += 1;
        }

        let old_regs = (old_len as usize + 7) / 8;
        let new_regs = (new_len as usize + 7) / 8;
        if 5 + old_regs + new_regs > 20 {
            return -36; // ENAMETOOLONG
        }

        msg.regs[0] = olddirfd as u32 as u64;
        msg.regs[1] = newdirfd as u32 as u64;
        msg.regs[2] = old_len as u64;
        msg.regs[3] = new_len as u64;
        msg.regs[4] = flags as u32 as u64;

        // Pack target (old path) bytes at regs[5..]
        for i in 5..20 {
            msg.regs[i] = 0;
        }
        let dst_target = &mut msg.regs[5] as *mut u64 as *mut u8;
        for i in 0..old_len as usize {
            *dst_target.add(i) = *oldpath.add(i);
        }
        // Pack link (new path) bytes immediately after target (8-byte aligned)
        let dst_link = (&mut msg.regs[5 + old_regs]) as *mut u64 as *mut u8;
        for i in 0..new_len as usize {
            *dst_link.add(i) = *newpath.add(i);
        }
        msg.length = 5 + (old_regs as u64) + (new_regs as u64);

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
