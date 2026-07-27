// SPDX-License-Identifier: GPL-2.0-only
//! POSIX poll, select, and epoll wrappers.

use crate::types::*;
use crate::*;
use trona_kernel::core_types::*;
use trona_protocol::posix::*;

/// Wait for events on a set of file descriptors (max 8 per call).
///
/// Packs (fd, events) pairs into IPC registers. On return, `revents` in each
/// `PollFd` is populated with the triggered event mask. `timeout` is in
/// milliseconds (-1 = block indefinitely). Returns the number of ready fds,
/// or -1 on error.
pub unsafe fn posix_poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS public poll wire (server `personality/posix/poll/entry.rs::handle`):
        //   regs[0] = nfds
        //   regs[1] = timeout_ns (relative duration; u64::MAX == block, 0 == nonblock)
        //   regs[2 + i*3]     = fd[i]
        //   regs[2 + i*3 + 1] = events[i]
        //   regs[2 + i*3 + 2] = revents[i] (0 on request; echoed back in reply)
        msg.label = VFS_POSIX_POLL;

        let actual_nfds = if nfds > 8 { 8 } else { nfds };
        msg.regs[0] = actual_nfds as u64;
        msg.regs[1] = if timeout < 0 {
            u64::MAX
        } else {
            (timeout as u64).saturating_mul(1_000_000)
        };

        // Pack (fd, events, revents=0) triples into regs[2..], matching the
        // server's 3-reg-per-entry echo wire.
        for i in 0..actual_nfds as usize {
            msg.regs[2 + i * 3] = (*fds.add(i)).fd as u64;
            msg.regs[2 + i * 3 + 1] = (*fds.add(i)).events as u64;
            msg.regs[2 + i * 3 + 2] = 0;
        }
        msg.length = 2 + actual_nfds as u64 * 3;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err == (uapi::KERNITE_ERR_INTERRUPTED as u64) as i32 {
            return -4; // EINTR
        }
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }

        let ready_count = reply.regs[0] as i32;
        // Reply echoes the 3-reg (fd, events, revents) triple per entry; revents
        // is the third word. regs[1] carries the entry count, not revents.
        for i in 0..actual_nfds as usize {
            (*fds.add(i)).revents = reply.regs[2 + i * 3 + 2] as i16;
        }

        ready_count
    }
}

/// Synchronous I/O multiplexing via fd_set bitmasks.
///
/// Implemented by converting `readfds`/`writefds` bitmasks to a poll array,
/// calling `posix_poll`, then rebuilding the bitmasks from results. Supports
/// up to 64 fds (single u64 bitmask). Returns the number of ready fds, or
/// -1 on error.
pub unsafe fn posix_select(nfds: i32, readfds: *mut u64, writefds: *mut u64, timeout: i32) -> i32 {
    unsafe {
        // Simple implementation: convert fd_sets to poll array
        let mut poll_fds: [PollFd; 8] = [PollFd::zeroed(); 8];
        let mut count: u32 = 0;

        let max_fd = if nfds > 64 { 64 } else { nfds };
        for fd in 0..max_fd {
            let mut events: i16 = 0;
            if !readfds.is_null() && (*readfds & (1u64 << fd)) != 0 {
                events |= crate::POLLIN;
            }
            if !writefds.is_null() && (*writefds & (1u64 << fd)) != 0 {
                events |= crate::POLLOUT;
            }
            if events != 0 && count < 8 {
                poll_fds[count as usize].fd = fd;
                poll_fds[count as usize].events = events;
                count += 1;
            }
        }

        if count == 0 {
            return 0;
        }

        let ret = posix_poll(poll_fds.as_mut_ptr(), count, timeout);
        if ret < 0 {
            return ret;
        }

        // Clear and rebuild fd_sets from revents
        if !readfds.is_null() {
            *readfds = 0;
        }
        if !writefds.is_null() {
            *writefds = 0;
        }

        let mut ready = 0;
        for i in 0..count as usize {
            if poll_fds[i].revents != 0 {
                let fd = poll_fds[i].fd;
                let mut counted = false;
                if !readfds.is_null()
                    && (poll_fds[i].revents & (crate::POLLIN | crate::POLLHUP | crate::POLLERR))
                        != 0
                {
                    *readfds |= 1u64 << fd;
                    if !counted {
                        ready += 1;
                        counted = true;
                    }
                }
                if !writefds.is_null() && (poll_fds[i].revents & crate::POLLOUT) != 0 {
                    *writefds |= 1u64 << fd;
                    if !counted {
                        ready += 1;
                    }
                }
            }
        }
        ready
    }
}

/// Create an epoll instance. Returns the epoll fd, or -1 on error.
pub unsafe fn posix_epoll_create() -> i32 {
    unsafe {
        crate::signals::posix_sigcheck();
        loop {
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            // VFS public epoll_create wire (`fileops/epoll.rs::handle`):
            //   regs[0] = flags (POSIX epoll_create takes no flags;
            //             pass 0 — epoll_create1 wrappers can override).
            msg.label = VFS_POSIX_EPOLL_CREATE;
            msg.length = 1;
            msg.regs[0] = 0;

            let err = trona_kernel::ipc::mp_call_ctx(
                crate::tls::current_ipc_ctx(),
                trona_runtime::client::caps::vfs_ep().addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            // No INTERRUPTED re-send: the kernel reply-wait owns resume, and
            // re-sending epoll_create would risk a duplicate fd.
            if err != 0 {
                return super::call_err_to_posix(err);
            }
            if reply.label != (uapi::KERNITE_OK as u64) {
                return super::trona_err_to_posix(reply.label);
            }
            return reply.regs[0] as i32;
        }
    }
}

/// Control an epoll instance: add/modify/delete `fd` with `events`/`data`.
/// `op` is EPOLL_CTL_ADD/MOD/DEL. Returns 0 on success, -1 on error.
pub unsafe fn posix_epoll_ctl(epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = VFS_POSIX_EPOLL_CTL;
        msg.length = 5;
        msg.regs[0] = epfd as u64;
        msg.regs[1] = op as u64;
        msg.regs[2] = fd as u64;
        msg.regs[3] = events as u64;
        msg.regs[4] = data;

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

/// Wait for events on an epoll instance.
///
/// Blocks until at least one event is ready or `timeout` milliseconds elapse.
/// Returns the number of ready events written to `events`, or -1 on error.
pub unsafe fn posix_epoll_wait(
    epfd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout: i32,
) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // VFS public epoll_wait wire (`fileops/epoll.rs::handle`):
        //   regs[0] = epfd
        //   regs[1] = max_events
        //   regs[2] = timeout_ns (i64::MIN == block; 0 == nonblock)
        msg.label = VFS_POSIX_EPOLL_WAIT;
        msg.length = 3;
        msg.regs[0] = epfd as u64;
        msg.regs[1] = maxevents as u64;
        msg.regs[2] = if timeout < 0 {
            i64::MIN as u64
        } else {
            (timeout as u64).saturating_mul(1_000_000)
        };

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::tls::current_ipc_ctx(),
            trona_runtime::client::caps::vfs_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err == (uapi::KERNITE_ERR_INTERRUPTED as u64) as i32 {
            return -4; // EINTR
        }
        if err != 0 {
            return super::call_err_to_posix(err);
        }
        if reply.label != (uapi::KERNITE_OK as u64) {
            return super::trona_err_to_posix(reply.label);
        }

        let count = reply.regs[0] as i32;
        // Unpack events: reply.regs[1+i*2] = events, reply.regs[2+i*2] = data
        for i in 0..count as usize {
            if !events.is_null() {
                (*events.add(i)).events = reply.regs[1 + i * 2] as u32;
                (*events.add(i)).data = reply.regs[2 + i * 2];
            }
        }
        count
    }
}
