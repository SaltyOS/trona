// SPDX-License-Identifier: GPL-2.0-only
//! POSIX fcntl, isatty, ioctl, chdir, getcwd, tcgetattr, shm operations.

use super::{pack_path, CAP_VFS_EP};
use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::protocol::*;
use trona::protocol::posix::*;
use trona::types::core::*;
use trona::types::posix::*;

#[repr(C)]
struct IoctlWinsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoctlSockAddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

#[repr(C)]
union IoctlIfreqUnion {
    addr: IoctlSockAddr,
    flags: i16,
    ifindex: i32,
}

#[repr(C)]
struct IoctlIfreq {
    name: [u8; 16],
    data: IoctlIfreqUnion,
}

#[repr(C)]
union IoctlIfconfBuf {
    buf: *mut u8,
    req: *mut IoctlIfreq,
}

#[repr(C)]
struct IoctlIfconf {
    len: i32,
    data: IoctlIfconfBuf,
}

const SIOCGIFCONF: u64 = 0x8912;
const SIOCGIFNAME: u64 = 0x8910;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCGIFADDR: u64 = 0x8915;
const SIOCGIFBRDADDR: u64 = 0x8919;
const SIOCGIFNETMASK: u64 = 0x891B;
const SIOCGIFINDEX: u64 = 0x8933;
const AF_INET: u16 = 2;
const IFF_UP: i16 = 0x1;
const IFF_BROADCAST: i16 = 0x2;
const IFF_RUNNING: i16 = 0x40;
const IFF_MULTICAST: i16 = 0x1000;

fn is_net_ioctl(request: u64) -> bool {
    matches!(
        request,
        SIOCGIFNAME
            | SIOCGIFCONF
            | SIOCGIFFLAGS
            | SIOCGIFADDR
            | SIOCGIFBRDADDR
            | SIOCGIFNETMASK
            | SIOCGIFINDEX
    )
}

unsafe fn read_ifreq_name(arg: u64) -> Option<[u8; 16]> {
    if arg == 0 {
        return None;
    }
    let mut out = [0u8; 16];
    let src = arg as *const u8;
    let mut i = 0usize;
    while i < 16 {
        out[i] = unsafe { *src.add(i) };
        if out[i] == 0 {
            break;
        }
        i += 1;
    }
    Some(out)
}

fn ifreq_name_is_eth0(name: &[u8; 16]) -> bool {
    name[0] == b'e'
        && name[1] == b't'
        && name[2] == b'h'
        && name[3] == b'0'
}

unsafe fn write_sockaddr_in(addr: *mut IoctlSockAddr, ip: u32) {
    unsafe {
        (*addr).sa_family = AF_INET;
        (*addr).sa_data.fill(0);
        let be = ip.to_be_bytes();
        (*addr).sa_data[2] = be[0];
        (*addr).sa_data[3] = be[1];
        (*addr).sa_data[4] = be[2];
        (*addr).sa_data[5] = be[3];
    }
}

pub unsafe fn posix_net_get_config(result: *mut [u64; 9]) -> i32 {
    unsafe {
        if result.is_null() {
            return -22;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = NET_GET_CONFIG;
        let err = crate::ipc_call_retry_idempotent(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        let out = &mut *result;
        let mut i = 0usize;
        while i < 9 {
            out[i] = reply.regs[i];
            i += 1;
        }
        0
    }
}

/// File control operations (F_GETFL, F_SETFL, F_DUPFD, etc.).
/// Returns the result value on success, -1 on error.
pub unsafe fn posix_fcntl(fd: i32, cmd: i32, arg: i64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_FCNTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = cmd as u64;
        msg.regs[2] = arg as u64;

        let err = crate::ipc_call_retry_idempotent(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Test whether `fd` refers to a terminal. Returns 1 if yes, 0 if not.
pub unsafe fn posix_isatty(fd: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_ISATTY;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc_call_retry_idempotent(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return 0;
        }
        reply.regs[0] as i32
    }
}

/// Generic device I/O control. Returns the result value, or -1 on error.
pub unsafe fn posix_ioctl(fd: i32, request: u64, arg: u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_IOCTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = request;
        msg.regs[2] = arg;

        let err = crate::ipc_call_retry(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }

        match request {
            SIOCGIFNAME => {
                if arg == 0 {
                    return -22;
                }
                let ifr = arg as *mut IoctlIfreq;
                if (*ifr).data.ifindex != 1 {
                    return -19;
                }
                (*ifr).name = [0; 16];
                (*ifr).name[0] = b'e';
                (*ifr).name[1] = b't';
                (*ifr).name[2] = b'h';
                (*ifr).name[3] = b'0';
                return 0;
            }
            SIOCGIFCONF => {
                if arg == 0 {
                    return -22;
                }
                let ifc = arg as *mut IoctlIfconf;
                if (*ifc).len < ::core::mem::size_of::<IoctlIfreq>() as i32 {
                    (*ifc).len = ::core::mem::size_of::<IoctlIfreq>() as i32;
                    return 0;
                }
                let dst = (*ifc).data.req;
                if dst.is_null() {
                    (*ifc).len = ::core::mem::size_of::<IoctlIfreq>() as i32;
                    return 0;
                }
                (*dst).name = [0; 16];
                (*dst).name[0] = b'e';
                (*dst).name[1] = b't';
                (*dst).name[2] = b'h';
                (*dst).name[3] = b'0';
                write_sockaddr_in(&mut (*dst).data.addr, reply.regs[0] as u32);
                (*ifc).len = ::core::mem::size_of::<IoctlIfreq>() as i32;
                return 0;
            }
            SIOCGIFFLAGS | SIOCGIFADDR | SIOCGIFBRDADDR | SIOCGIFNETMASK | SIOCGIFINDEX => {
                let ifr_name = match read_ifreq_name(arg) {
                    Some(name) => name,
                    None => return -22,
                };
                if !ifreq_name_is_eth0(&ifr_name) {
                    return -19;
                }
                let ifr = arg as *mut IoctlIfreq;
                match request {
                    SIOCGIFFLAGS => {
                        (*ifr).data.flags = reply.regs[0] as i16;
                    }
                    SIOCGIFINDEX => {
                        (*ifr).data.ifindex = reply.regs[0] as i32;
                    }
                    SIOCGIFADDR | SIOCGIFBRDADDR | SIOCGIFNETMASK => {
                        write_sockaddr_in(&mut (*ifr).data.addr, reply.regs[0] as u32);
                    }
                    _ => {}
                }
                return 0;
            }
            TIOCGPGRP => {
                if arg != 0 {
                    let pgrp_p = arg as *mut i32;
                    *pgrp_p = reply.regs[0] as i32;
                    return 0;
                }
            }
            TIOCGWINSZ => {
                if arg != 0 {
                    let rows = if reply.length >= 1 { reply.regs[0] } else { 0 };
                    let cols = if reply.length >= 2 { reply.regs[1] } else { 0 };

                    let ws = arg as *mut IoctlWinsize;
                    (*ws).ws_row = rows as u16;
                    (*ws).ws_col = cols as u16;
                    (*ws).ws_xpixel = 0;
                    (*ws).ws_ypixel = 0;
                    return 0;
                }
            }
            _ => {}
        }
        reply.regs[0] as i32
    }
}

/// Change the current working directory to `path`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_chdir(path: *const u8) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_CHDIR;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc_call_retry(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Get the current working directory, writing the null-terminated path
/// into `buf` (up to `size` bytes). Returns 0 on success, -1 on error.
pub unsafe fn posix_getcwd(buf: *mut u8, size: u64) -> i32 {
    unsafe {
        if buf.is_null() || size == 0 {
            return -1;
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_GETCWD;
        msg.length = 1;
        msg.regs[0] = size;

        let err = crate::ipc_call_retry_idempotent(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }

        let path_len = reply.regs[0] as usize;
        let size_usize = size as usize;
        if path_len + 1 > size_usize {
            return -1;
        }
        let reply_data_bytes = (reply.length.saturating_sub(1) * 8) as usize;
        if path_len > reply_data_bytes {
            return -1;
        }

        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..path_len {
            *buf.add(i) = *src.add(i);
        }
        *buf.add(path_len) = 0;
        0
    }
}

/// Get terminal attributes for fd into `*termios_p`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_tcgetattr(fd: i32, termios_p: *mut Termios) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_TCGETATTR;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc_call_retry_idempotent(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }

        // Unpack: regs[0]=c_iflag, regs[1]=c_oflag, regs[2]=c_cflag, regs[3]=c_lflag
        // regs[4]=c_ispeed, regs[5]=c_ospeed, regs[6..9]=c_cc[0..31] packed as 4 u64s
        (*termios_p).c_iflag = reply.regs[0] as u32;
        (*termios_p).c_oflag = reply.regs[1] as u32;
        (*termios_p).c_cflag = reply.regs[2] as u32;
        (*termios_p).c_lflag = reply.regs[3] as u32;
        (*termios_p).c_ispeed = reply.regs[4] as u32;
        (*termios_p).c_ospeed = reply.regs[5] as u32;
        (*termios_p).c_line = 0;
        // Unpack c_cc from regs[6..9] (4 u64s = 32 bytes)
        let src = &reply.regs[6] as *const u64 as *const u8;
        for i in 0..32 {
            (*termios_p).c_cc[i] = *src.add(i);
        }
        0
    }
}

/// Set terminal attributes for fd from `*termios_p`.
/// `action` controls when changes take effect (TCSANOW/TCSADRAIN/TCSAFLUSH).
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_tcsetattr(
    fd: i32,
    action: i32,
    termios_p: *const Termios,
) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_TCSETATTR;
        msg.length = 11;
        msg.regs[0] = fd as u64;
        msg.regs[1] = action as u64;
        msg.regs[2] = (*termios_p).c_iflag as u64;
        msg.regs[3] = (*termios_p).c_oflag as u64;
        msg.regs[4] = (*termios_p).c_cflag as u64;
        msg.regs[5] = (*termios_p).c_lflag as u64;
        msg.regs[6] = (*termios_p).c_ispeed as u64;
        msg.regs[7] = (*termios_p).c_ospeed as u64;
        // Pack c_cc into regs[8..11] (4 u64s = 32 bytes)
        let dst = &mut msg.regs[8] as *mut u64 as *mut u8;
        for i in 0..32 {
            *dst.add(i) = (*termios_p).c_cc[i];
        }

        let err = crate::ipc_call_retry(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Open a POSIX shared memory object by `name` (e.g. "/myshm").
///
/// Strips the leading '/' per POSIX convention before sending to VFS.
/// Returns the shm fd on success, -1 on error.
pub unsafe fn posix_shm_open(name: *const u8, flags: i32) -> i32 {
    unsafe {
        // POSIX: shm names are "/name"; strip leading '/' before sending bare name to VFS
        let bare = if !name.is_null() && *name == b'/' {
            name.add(1)
        } else {
            name
        };
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_SHM_OPEN;
        msg.regs[0] = flags as u64;
        let name_len = pack_path(&raw mut msg, 1, bare, 128);
        msg.length = 2 + ((name_len as u64 + 7) / 8);

        let err = crate::ipc_call_retry(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Remove a POSIX shared memory object by name.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_shm_unlink(name: *const u8) -> i32 {
    unsafe {
        // POSIX: shm names are "/name"; strip leading '/' before sending bare name to VFS
        let bare = if !name.is_null() && *name == b'/' {
            name.add(1)
        } else {
            name
        };
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_SHM_UNLINK;
        let name_len = pack_path(&raw mut msg, 0, bare, 128);
        msg.length = 1 + ((name_len as u64 + 7) / 8);

        let err = crate::ipc_call_retry(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// Framebuffer ioctl wrapper.
///
/// Sends VFS_IOCTL with an fb-specific command and unpacks up to 5 result registers.
pub unsafe fn posix_fb_ioctl(fd: i32, cmd: u64, result: *mut [u64; 5]) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_IOCTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = cmd;
        msg.regs[2] = 0;

        let err = crate::ipc_call_retry(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        if !result.is_null() {
            for i in 0..5 {
                (*result)[i] = reply.regs[i];
            }
        }
        0
    }
}

// Process-local umask cache. Fork copies the address space, so children
// inherit the value automatically. Single-threaded processes only.
static mut UMASK_CACHE: u32 = 0o022;

/// Return the current cached umask value.
pub(crate) unsafe fn get_umask() -> u32 {
    unsafe { ::core::ptr::read_volatile(&raw const UMASK_CACHE) }
}

/// Set the file creation mask. Returns the previous mask.
///
/// IPC to procmgr: regs[0] = new mask. Reply: regs[0] = old mask.
/// Also updates the local cache so file creation functions can apply it
/// without an extra IPC round-trip.
pub unsafe fn posix_umask(mask: u32) -> u32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = PM_UMASK;
        msg.length = 1;
        msg.regs[0] = mask as u64;

        let cap_procmgr: u64 = 3; // CAP_PROCMGR_EP
        let err = crate::ipc_call_retry(cap_procmgr, &raw const msg, &raw mut reply);
        let old = if err != 0 || reply.label != TRONA_OK {
            let prev = ::core::ptr::read_volatile(&raw const UMASK_CACHE);
            ::core::ptr::write_volatile(&raw mut UMASK_CACHE, mask & 0o777);
            prev
        } else {
            ::core::ptr::write_volatile(&raw mut UMASK_CACHE, mask & 0o777);
            reply.regs[0] as u32
        };
        old
    }
}

/// fchmod(fd, mode) — change mode on open fd
/// IPC: reg[0]=fd, reg[1]=mode
pub unsafe fn posix_fchmod(fd: i32, mode: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_FCHMOD;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = mode as u64;

        let err = crate::ipc_call_retry(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}

/// fchown(fd, uid, gid) — change owner on open fd
/// IPC: reg[0]=fd, reg[1]=uid, reg[2]=gid
pub unsafe fn posix_fchown(fd: i32, uid: u32, gid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_FCHOWN;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = uid as u64;
        msg.regs[2] = gid as u64;

        let err = crate::ipc_call_retry(CAP_VFS_EP, &raw const msg, &raw mut reply);
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != TRONA_OK {
            return super::trona_err_to_posix(reply.label);
        }
        0
    }
}
