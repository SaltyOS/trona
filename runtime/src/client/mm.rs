//! Personality-neutral memory-management IPC helpers.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! These functions talk to mmsrv and return SaltyOS `TRONA_*` labels instead
//! of POSIX errno values.

use crate::core::slot_alloc::{OwnedCap, TransferCap, forward_external, resolved_cap_ref};
use trona_kernel::core_types::{CapRef, TronaMsg};
use trona_protocol::common::TRONA_OK;
use trona_protocol::mm::*;
use trona_protocol::posix_abi::mm::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_LAZY, MAP_PRIVATE, MAP_STACK,
};
use trona_protocol::vfs::public::{
    VFS_BACKING_MO_REPLY_REG_BACKING_ID, VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH,
    VFS_BACKING_MO_REPLY_REG_COUNT, VFS_BACKING_MO_REPLY_REG_MMAP_KIND,
    VFS_BACKING_MO_REPLY_REG_OFFSET, VFS_GET_BACKING_MO,
};

pub type Result<T> = core::result::Result<T, u64>;

static mut BACKING_MO_RECV_SLOT: u64 = 0;

#[inline]
fn call_error(err: i32) -> u64 {
    err as u64
}

/// Sticky per-process receive slot for the file-backed mmap backing MO cap.
///
/// Allocated once and cached in `BACKING_MO_RECV_SLOT`; reused across every
/// `mmap` call. This is a sticky receive-scratch slot, *not* a per-call owned
/// cap — the cap that lands in it is forwarded out on the same call (see
/// [`forward_external`]), so the slot itself is recycled rather than freed.
unsafe fn backing_mo_recv_slot() -> Result<u64> {
    unsafe {
        let slot = *(&raw const BACKING_MO_RECV_SLOT);
        if slot != 0 {
            return Ok(slot);
        }
        let Some(new_slot) = crate::core::slot_alloc::slot_alloc() else {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as u64);
        };
        *(&raw mut BACKING_MO_RECV_SLOT) = new_slot;
        Ok(new_slot)
    }
}

fn clear_backing_mo_recv_slot(slot: u64) {
    // Resolve the slot's invoke depth so an expanded-CSpace slot (depth > 0)
    // is targeted correctly rather than mis-deleted at the root.
    let depth = crate::core::slot_alloc::slot_invoke_depth(slot);
    let _ = trona_kernel::invoke::cnode_delete_depth(
        CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
        slot,
        depth,
    );
}

fn mmsrv_flags_from_posix(flags: i32) -> u64 {
    let mut out = 0;
    if flags & MAP_FIXED != 0 {
        out |= MM_FLAG_FIXED;
    }
    if flags & MAP_FIXED_NOREPLACE != 0 {
        out |= MM_FLAG_FIXED;
        out |= MM_FLAG_FIXED_NOREPLACE;
    }
    if flags & MAP_LAZY != 0 {
        out |= MM_FLAG_LAZY;
    }
    if flags & MAP_PRIVATE != 0 {
        out |= MM_FLAG_PRIVATE;
    }
    out
}

fn anon_kind_from_posix(flags: i32) -> u64 {
    if flags & MAP_STACK != 0 {
        MMAP_KIND_ANON_STACK
    } else {
        MMAP_KIND_ANON
    }
}

/// Reserve a free VA range of `length` bytes (aligned to `align`, or
/// page-aligned when `align` is 0) inside `[bounds_lo, bounds_hi)` in the
/// caller's own VM, letting mmsrv choose the base. The chosen range is
/// collision-free by construction (the gap allocator skips occupied
/// intervals), so a self-managed window placed here cannot overlap the
/// fixed VA windows the bounds were drawn from. Returns the chosen base.
///
/// # Safety
/// Issues an IPC to mmsrv; the caller must be a registered mmsrv client.
pub unsafe fn alloc_range(
    length: u64,
    align: u64,
    bounds_lo: u64,
    bounds_hi: u64,
    kind: u64,
) -> Result<u64> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_ALLOC_RANGE;
        msg.length = 5;
        msg.regs[0] = length;
        msg.regs[1] = align;
        msg.regs[2] = bounds_lo;
        msg.regs[3] = bounds_hi;
        msg.regs[4] = kind;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0])
    }
}

/// Set the current process break.
///
/// # Safety
/// The caller must ensure `addr` is a valid program-break value for the
/// current process address space.
pub unsafe fn brk(addr: u64) -> Result<()> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_BRK;
        msg.length = 1;
        msg.regs[0] = addr;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
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

/// Increment the current process break.
///
/// # Safety
/// The caller must ensure the resulting program break remains valid for the
/// current process address space.
pub unsafe fn sbrk(increment: i64) -> Result<u64> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_SBRK;
        msg.length = 1;
        msg.regs[0] = increment as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
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
        Ok(reply.regs[0])
    }
}

/// Map memory in the current process.
///
/// Two-step flow for file-backed mmap:
///   1. `VFS_GET_BACKING_MO(fd, offset, length)` against vfs returns
///      the pager-attached MO cap in the armed receive slot.
///   2. `MM_MMAP(kind=MMAP_KIND_MO, caps[0]=mo_cap, hint, length,
///      prot, flags, mo_offset)` against the caller's per-client
///      mmsrv MP lands the MO in the caller's vspace.
///
/// Anonymous mmap (`fd == -1` or `MAP_ANONYMOUS`) is a single
/// `MM_MMAP(kind=MMAP_KIND_ANON, ...)` against mmsrv; vfs is not on
/// the path.
///
/// # Safety
/// The caller must ensure the requested address range, flags, file descriptor,
/// and offset are valid for the current process.
pub unsafe fn mmap(
    addr: *mut u8,
    length: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<*mut u8> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        if length == 0 {
            return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
        }

        if fd >= 0 && (flags & MAP_ANONYMOUS) == 0 {
            if offset < 0 {
                return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
            }
            let vfs = crate::client::caps::vfs_ep();
            if vfs.is_null() {
                return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
            }

            // Step 1 — VFS_GET_BACKING_MO(fd, offset, length) →
            // mo_cap in the armed receive slot. vfs miss issues
            // MM_FILE_MMAP to mmsrv internally to retype the
            // MO and attach the pager.
            let mut req = TronaMsg::zeroed();
            let mut rsp = TronaMsg::zeroed();
            req.label = VFS_GET_BACKING_MO;
            req.length = 3;
            req.regs[0] =
                u64::try_from(fd).map_err(|_| uapi::KERNITE_ERR_INVALID_ARGUMENT as u64)?;
            req.regs[1] =
                u64::try_from(offset).map_err(|_| uapi::KERNITE_ERR_INVALID_ARGUMENT as u64)?;
            req.regs[2] = length;

            let mo_cap = backing_mo_recv_slot()?;
            clear_backing_mo_recv_slot(mo_cap);
            crate::core::ipc_ext::set_receive_slot_ctx(
                crate::current_ipc_ctx(),
                uapi::KERNITE_CAP_SELF_CSPACE as u64,
                mo_cap,
                0,
            );
            let err = trona_kernel::ipc::mp_call_ctx(
                crate::current_ipc_ctx(),
                vfs.addr(),
                &raw const req,
                &raw mut rsp,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            if err != 0 {
                clear_backing_mo_recv_slot(mo_cap);
                return Err(call_error(err));
            }
            if rsp.label != TRONA_OK {
                clear_backing_mo_recv_slot(mo_cap);
                return Err(rsp.label);
            }

            // Step 2 — MM_MMAP(kind=MO/DEVICE, caps[0]=backing_cap, ...)
            // → mapped_va on reply.regs[0]. Regular files return an
            // MO cap; device files such as /dev/fb0 return a device
            // untyped cap and set regs[2] to MMAP_KIND_DEVICE.
            if rsp.length < VFS_BACKING_MO_REPLY_REG_COUNT {
                clear_backing_mo_recv_slot(mo_cap);
                return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
            }
            let mmap_kind = rsp.regs[VFS_BACKING_MO_REPLY_REG_MMAP_KIND];
            if mmap_kind != MMAP_KIND_MO
                && mmap_kind != MMAP_KIND_SHM_MO
                && mmap_kind != MMAP_KIND_DEVICE
            {
                clear_backing_mo_recv_slot(mo_cap);
                return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
            }
            let backing_offset = rsp.regs[VFS_BACKING_MO_REPLY_REG_OFFSET];
            let backing_id = rsp.regs[VFS_BACKING_MO_REPLY_REG_BACKING_ID];
            let backing_length = rsp.regs[VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH];
            let mut msg = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            msg.label = MM_MMAP;
            msg.length = 10;
            msg.regs[0] = mmap_kind;
            msg.regs[1] = addr as u64;
            msg.regs[2] = length;
            msg.regs[3] = prot as u64;
            msg.regs[4] = mmsrv_flags_from_posix(flags);
            msg.regs[5] = backing_offset;
            msg.regs[MM_MMAP_REQ_REG_FILE_BACKING_ID] = backing_id;
            msg.regs[MM_MMAP_REQ_REG_FILE_BACKING_LENGTH] = backing_length;

            // The backing cap lives in the sticky receive slot; forward it
            // out of that slot for this one send (the kernel moves it into
            // mmsrv; the slot is rearmed on the next call).
            // SAFETY (within this fn's enclosing unsafe block): `mo_cap` is the
            // client's sticky backing-MO receive slot (rearmed by
            // clear_backing_mo_recv_slot below), not a slot any live OwnedCap owns
            // — exactly the external-rearmer case forward_external requires; the
            // send moves the cap out and the slot is not freed.
            let fwd = forward_external(resolved_cap_ref(mo_cap));
            let ctx = crate::current_ipc_ctx();
            trona_kernel::ipc::clear_send_caps_ctx(ctx);
            trona_kernel::ipc::set_send_cap_ctx(ctx, 0, fwd.slot());
            let err = trona_kernel::ipc::mp_call_ctx(
                ctx,
                mmsrv.addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            );
            trona_kernel::ipc::clear_send_caps_ctx(ctx);
            clear_backing_mo_recv_slot(mo_cap);
            if err != 0 {
                return Err(call_error(err));
            }
            if reply.label != TRONA_OK {
                return Err(reply.label);
            }
            return Ok(reply.regs[0] as *mut u8);
        }

        if (flags & MAP_ANONYMOUS) == 0 {
            return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MMAP;
        msg.length = 5;
        msg.regs[0] = anon_kind_from_posix(flags);
        msg.regs[1] = addr as u64;
        msg.regs[2] = length;
        msg.regs[3] = prot as u64;
        msg.regs[4] = mmsrv_flags_from_posix(flags);

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0] as *mut u8)
    }
}

/// Map anonymous memory in the current process.
///
/// # Safety
/// The caller must ensure the requested address range and flags are valid for
/// the current process.
pub unsafe fn mmap_anonymous(addr: *mut u8, length: u64, prot: i32, flags: i32) -> Result<*mut u8> {
    unsafe { mmap(addr, length, prot, flags | MAP_ANONYMOUS, -1, 0) }
}

/// Unmap memory in the current process.
///
/// # Safety
/// `addr..addr + length` must describe a mapping owned by the current process.
pub unsafe fn munmap(addr: *mut u8, length: u64) -> Result<()> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MUNMAP;
        msg.length = 2;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
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

/// Synchronize a mapped range in the current process.
///
/// # Safety
/// `addr..addr + length` must describe a mapping owned by the current process.
pub unsafe fn msync(addr: *mut u8, length: u64, flags: i32) -> Result<()> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MSYNC;
        msg.length = 3;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;
        msg.regs[2] = flags as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

/// Change protection flags on a current-process mapping.
///
/// # Safety
/// `addr..addr + length` must describe a mapping owned by the current process.
pub unsafe fn mprotect(addr: *mut u8, length: u64, prot: i32) -> Result<()> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MPROTECT;
        msg.length = 3;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;
        msg.regs[2] = prot as u64;

        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
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

/// Create a shared-memory region through mmsrv.
///
/// Single source of truth for the `MM_SHM_CREATE` wire format
/// (`regs[0]=name, regs[1]=0, regs[2]=size_bytes`, three registers) so SHM
/// clients cannot drift: the size MUST travel in `regs[2]`, and the receive
/// slot for the returned MO cap MUST be armed before the call. A freshly
/// allocated slot receives the cap.
///
/// The receive slot is saved before and restored after the call, so a server
/// reactor's sticky receive slot is left untouched.
///
/// On success returns `(shm_idx, shm_cap)`. The [`OwnedCap`] owns the returned
/// MO cap; dropping it releases the region's local cap.
pub fn shm_create(name: u64, bytes: u64) -> Result<(u64, OwnedCap)> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        let cap = crate::core::slot_alloc::alloc_slot_or_idle(b"shm mo cap");

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_SHM_CREATE;
        msg.length = 3;
        msg.regs[0] = name;
        msg.regs[1] = 0;
        msg.regs[2] = bytes;

        // Save the caller's receive slot, arm ours for the returned MO cap,
        // then restore — a server reactor's sticky receive slot is preserved.
        let saved = trona_kernel::ipc::get_receive_slot_path_ctx(crate::current_ipc_ctx());
        crate::core::ipc_ext::set_receive_slot_ctx(
            crate::current_ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            cap.addr(),
            0,
        );
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
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
        // The slot was armed to receive the MO cap, so treat it as potentially
        // occupied from here: `OwnedCap`'s drop deletes any delivered
        // cap (and no-ops + frees an empty slot), preserving the defensive
        // teardown the failure paths need should a cap ever ride a non-OK reply.
        let cap = cap.assume_filled();
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok((reply.regs[0], cap))
    }
}

/// Map a shared-memory region into the current address space through mmsrv.
///
/// Single source of truth for the `MM_SHM_MAP` wire format
/// (`regs[0]=place, regs[1]=shm_idx, regs[2]=offset(0), regs[3]=size_bytes,
/// regs[4]=prot, regs[5]=0`, six registers, one staged send cap). Serves both
/// the producer role (map the region you just created) and the consumer role
/// (map a cap a peer produced).
///
/// `map_cap` is consumed: its slot is staged into the send window and the
/// kernel moves the cap into mmsrv. Pass `owned.duplicate_for_transfer()` to
/// keep a retained cap live, or `owned.into_transfer()` to give it up.
/// `place` is `0` for mmsrv auto-placement or a fixed VA hint.
pub fn shm_map(
    shm_idx: u64,
    map_cap: TransferCap,
    place: u64,
    bytes: u64,
    prot: u64,
) -> Result<u64> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_SHM_MAP;
        msg.length = 6;
        msg.regs[0] = place;
        msg.regs[1] = shm_idx;
        msg.regs[2] = 0;
        msg.regs[3] = bytes;
        msg.regs[4] = prot;
        msg.regs[5] = 0;

        let ctx = crate::current_ipc_ctx();
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
        trona_kernel::ipc::set_send_cap_ctx(ctx, 0, map_cap.slot());
        let err = trona_kernel::ipc::mp_call_ctx(
            ctx,
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
        // `map_cap` drops here → reclaims the now-empty (moved-out) or
        // rolled-back slot.
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0])
    }
}

/// Reserve a contiguous image load-envelope `[base, base + bytes)` in the
/// caller's own VSpace (`MM_RESERVE_IMAGE`). The returned packed reservation id
/// is the image handle: each run mapped into the envelope tags it (see
/// [`map_image_run_mo`] / [`map_image_run_anon`]), and [`unmap_image`] tears
/// the whole image down as a unit.
///
/// # Safety
/// Issues an IPC to mmsrv; the caller must be a registered mmsrv client.
pub unsafe fn reserve_image(base: u64, bytes: u64) -> Result<u64> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_RESERVE_IMAGE;
        msg.length = 2;
        msg.regs[0] = base;
        msg.regs[1] = bytes;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0])
    }
}

/// Tear down every region tagged with image reservation `image_id` and free the
/// reservation (`MM_UNMAP_IMAGE`). Used by `dlclose`.
///
/// # Safety
/// Issues an IPC to mmsrv; the caller must be a registered mmsrv client.
pub unsafe fn unmap_image(image_id: u64) -> Result<()> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_UNMAP_IMAGE;
        msg.length = 1;
        msg.regs[0] = image_id;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

/// Map one run of a resolved code object into a pre-reserved image envelope at
/// the fixed VA `va`, sourced from a caller-supplied MO cap (`MM_MMAP`
/// `kind=MMAP_KIND_MO`, `MM_FLAG_FIXED`, `regs[6]=image_id`,
/// `regs[7]=image_kind`). `private` adds `MM_FLAG_PRIVATE` for a copy-on-write
/// data run; a shared text / rodata run passes `false`. `run_cap` is the
/// rights-attenuated MO cap for this run and is consumed by the send (the kernel
/// moves it into mmsrv). `prot` is the run's POSIX protection — the kernel's
/// cap-derived ceiling refuses any mapping that exceeds `run_cap`'s rights,
/// which is what enforces W^X per run.
///
/// # Safety
/// Issues an IPC to mmsrv; `run_cap` must name a transferable MO cap whose
/// rights bound the requested `prot`.
pub unsafe fn map_image_run_mo(
    va: u64,
    size: u64,
    prot: u64,
    private: bool,
    mo_offset: u64,
    image_id: u64,
    image_kind: u64,
    run_cap: TransferCap,
) -> Result<()> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        let mut flags = MM_FLAG_FIXED;
        if private {
            flags |= MM_FLAG_PRIVATE;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MMAP;
        msg.length = 8;
        msg.regs[0] = MMAP_KIND_MO;
        msg.regs[1] = va;
        msg.regs[2] = size;
        msg.regs[3] = prot;
        msg.regs[4] = flags;
        msg.regs[5] = mo_offset;
        msg.regs[MM_MMAP_REQ_REG_IMAGE_ID] = image_id;
        msg.regs[MM_MMAP_REQ_REG_IMAGE_KIND] = image_kind;
        let ctx = crate::current_ipc_ctx();
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
        trona_kernel::ipc::set_send_cap_ctx(ctx, 0, run_cap.slot());
        let err = trona_kernel::ipc::mp_call_ctx(
            ctx,
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
        // run_cap drops here → reclaims the moved-out (or rolled-back) slot.
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

/// Map a zero-fill run (`.bss` / zero-padded rodata) into a pre-reserved image
/// envelope at the fixed VA `va` (`MM_MMAP` `kind=MMAP_KIND_ANON`,
/// `MM_FLAG_FIXED`, `regs[6]=image_id`, `regs[7]=image_kind`). No backing cap
/// — mmsrv allocates a fresh anonymous MO.
///
/// # Safety
/// Issues an IPC to mmsrv; the caller must be a registered mmsrv client.
pub unsafe fn map_image_run_anon(
    va: u64,
    size: u64,
    prot: u64,
    image_id: u64,
    image_kind: u64,
) -> Result<()> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MMAP;
        msg.length = 8;
        msg.regs[0] = MMAP_KIND_ANON;
        msg.regs[1] = va;
        msg.regs[2] = size;
        msg.regs[3] = prot;
        msg.regs[4] = MM_FLAG_FIXED;
        msg.regs[5] = 0;
        msg.regs[MM_MMAP_REQ_REG_IMAGE_ID] = image_id;
        msg.regs[MM_MMAP_REQ_REG_IMAGE_KIND] = image_kind;
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

/// Ask mmsrv to retype a fresh anonymous MemoryObject of `length` bytes
/// (`MM_MO_CREATE`) and return the cap. The caller owns the returned MO and may
/// map it, write it, confer rights on it, or transfer it. The receive slot is
/// saved/restored so a server reactor's sticky slot is preserved.
///
/// # Safety
/// Issues an IPC to mmsrv; the caller must be a registered mmsrv client.
pub unsafe fn mo_create(length: u64) -> Result<OwnedCap> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        let Some(cap) = crate::core::slot_alloc::alloc_slot() else {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as u64);
        };
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MO_CREATE;
        msg.length = 2;
        msg.regs[0] = length;
        msg.regs[1] = 0;
        let saved = trona_kernel::ipc::get_receive_slot_path_ctx(crate::current_ipc_ctx());
        crate::core::ipc_ext::set_receive_slot_ctx(
            crate::current_ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            cap.addr(),
            0,
        );
        let err = trona_kernel::ipc::mp_call_ctx(
            crate::current_ipc_ctx(),
            mmsrv.addr(),
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
        let cap = cap.assume_filled();
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(cap)
    }
}

/// Map a caller-supplied MemoryObject cap into the caller's own address space
/// (`MM_MMAP` `kind=MMAP_KIND_MO`). `hint == 0` lets mmsrv auto-place; a non-zero
/// `hint` is a `MM_FLAG_FIXED` placement. `mo_offset` is the page-aligned byte
/// offset into the MO. `cap` is consumed by the send. Returns the mapped VA.
///
/// # Safety
/// Issues an IPC to mmsrv; `cap` must name a transferable MO whose rights bound
/// `prot`.
pub unsafe fn mmap_mo(
    hint: u64,
    size: u64,
    prot: u64,
    mo_offset: u64,
    cap: TransferCap,
) -> Result<*mut u8> {
    unsafe {
        let mmsrv = crate::client::caps::mmsrv_ep();
        if mmsrv.is_null() {
            return Err(uapi::KERNITE_ERR_NOT_FOUND as u64);
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MMAP;
        msg.length = 6;
        msg.regs[0] = MMAP_KIND_MO;
        msg.regs[1] = hint;
        msg.regs[2] = size;
        msg.regs[3] = prot;
        msg.regs[4] = if hint != 0 { MM_FLAG_FIXED } else { 0 };
        msg.regs[5] = mo_offset;
        let ctx = crate::current_ipc_ctx();
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
        trona_kernel::ipc::set_send_cap_ctx(ctx, 0, cap.slot());
        let err = trona_kernel::ipc::mp_call_ctx(
            ctx,
            mmsrv.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
        if err != 0 {
            return Err(call_error(err));
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0] as *mut u8)
    }
}
