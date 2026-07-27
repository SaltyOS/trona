//! SPDX-License-Identifier: GPL-2.0-only
//! RTLD capability operations (frame allocation, VSpace mapping)

use crate::common::elf::types::PAGE_SIZE;
use crate::rtld::syscall::rtld_syscall6;

const CAP_SELF_VSPACE: u32 = uapi::KERNITE_CAP_SELF_VSPACE as u32;
const SYS_INVOKE: u64 = uapi::KERNITE_SYS_INVOKE as u64;
const TRONA_OUT_OF_MEMORY: u64 = uapi::KERNITE_ERR_OUT_OF_MEMORY as u64;
const TRONA_INVALID_CAPABILITY: u64 = uapi::KERNITE_ERR_INVALID_CAPABILITY as u64;
const TRONA_INVALID_OPERATION: u64 = uapi::KERNITE_ERR_INVALID_OPERATION as u64;
const TRONA_NOT_FOUND: u64 = uapi::KERNITE_ERR_NOT_FOUND as u64;

/// Allocates a single 4 KiB frame into `frame_slot` by retyping from the
/// mirrored RTLD untyped window.
///
/// # Safety
/// `frame_slot` must be unused.
pub unsafe fn alloc_frame_slot(
    next_untyped_slot: &mut u32,
    untyped_limit: u32,
    frame_slot: u32,
) -> u64 {
    let mut current_untyped = *next_untyped_slot;
    let mut last_err = TRONA_OUT_OF_MEMORY;
    loop {
        if current_untyped == 0 || current_untyped >= untyped_limit {
            return last_err;
        }
        let err = unsafe {
            invoke_untyped_retype(
                current_untyped,
                uapi::KERNITE_OBJ_FRAME as u32,
                0,
                frame_slot,
            )
        };
        match err {
            0 => {
                *next_untyped_slot = current_untyped;
                return 0;
            }
            TRONA_OUT_OF_MEMORY => {
                last_err = err;
                current_untyped = current_untyped.saturating_add(1);
            }
            TRONA_INVALID_CAPABILITY | TRONA_INVALID_OPERATION | TRONA_NOT_FOUND => {
                last_err = err;
                current_untyped = current_untyped.saturating_add(1);
            }
            _ => return err,
        }
    }
}

/// Maps an already-allocated frame capability into the current VSpace.
///
/// # Safety
/// `frame_slot` must contain a valid frame capability. `vaddr` must be page-
/// aligned and unmapped.
pub unsafe fn map_frame(frame_slot: u32, vaddr: usize, rights: u32) -> u64 {
    unsafe { invoke_vspace_map(CAP_SELF_VSPACE, frame_slot, vaddr, rights) }
}

/// Unmaps a single page from the current VSpace.
///
/// # Safety
/// `vaddr` must be page-aligned.
pub unsafe fn unmap_page(vaddr: usize) -> u64 {
    unsafe { invoke_vspace_unmap(CAP_SELF_VSPACE, vaddr) }
}

/// Allocates `count` contiguous frames and maps them starting at `vaddr`.
///
/// # Safety
/// All slots from `frame_slot_base` to `frame_slot_base + count` must be unused.
/// `vaddr` must be page-aligned, and the range must be unmapped.
pub unsafe fn alloc_and_map_range(
    next_untyped_slot: &mut u32,
    untyped_limit: u32,
    frame_slot_base: u32,
    vaddr: usize,
    count: usize,
    rights: u32,
) -> u64 {
    for i in 0..count {
        let slot = frame_slot_base + i as u32;
        let addr = vaddr + i * PAGE_SIZE;
        let err = unsafe { alloc_frame_slot(next_untyped_slot, untyped_limit, slot) };
        if err != 0 {
            return err;
        }
        let err = unsafe { map_frame(slot, addr, rights) };
        if err != 0 {
            return err;
        }
    }
    0
}

/// Raw invoke: Untyped.Retype.
///
/// RTLD uses the kernel's normal frame ABI: `OBJ_FRAME` with `size_bits = 0`
/// requests a single 4 KiB page, matching every other in-tree frame retype
/// caller.
///
/// # Safety
/// Caller must ensure valid capability slots.
unsafe fn invoke_untyped_retype(
    untyped_slot: u32,
    obj_type: u32,
    size_bits: u32,
    dest_slot: u32,
) -> u64 {
    let (error, _) = rtld_syscall6(
        SYS_INVOKE,
        untyped_slot as u64,
        uapi::KERNITE_INV_UNTYPED_RETYPE as u64,
        obj_type as u64,
        size_bits as u64,
        dest_slot as u64,
        0,
    );
    error
}

/// Raw invoke: VSpace.Map
///
/// # Safety
/// Caller must ensure valid capability slots and unmapped vaddr.
unsafe fn invoke_vspace_map(vspace_slot: u32, frame_slot: u32, vaddr: usize, rights: u32) -> u64 {
    let (error, _) = rtld_syscall6(
        SYS_INVOKE,
        vspace_slot as u64,
        uapi::KERNITE_INV_VSPACE_MAP as u64,
        frame_slot as u64,
        vaddr as u64,
        rights as u64,
        0,
    );
    error
}

/// Raw invoke: VSpace.Unmap
///
/// # Safety
/// Caller must ensure `vaddr` is page-aligned.
unsafe fn invoke_vspace_unmap(vspace_slot: u32, vaddr: usize) -> u64 {
    let (error, _) = rtld_syscall6(
        SYS_INVOKE,
        vspace_slot as u64,
        uapi::KERNITE_INV_VSPACE_UNMAP as u64,
        vaddr as u64,
        0,
        0,
        0,
    );
    error
}
