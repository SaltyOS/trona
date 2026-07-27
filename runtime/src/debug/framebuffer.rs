//! Framebuffer info reader for userspace
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Reads framebuffer metadata from the process startup block. Early
//! boot code can still fall back to the kernel boot info page when no
//! `AT_SALTYOS_STARTUP` block is installed.

use uapi::{KERNITE_BOOTINFO_TAG_FRAMEBUFFER, kernite_bootinfo_framebuffer};

use trona_kernel::bootinfo;
use trona_kernel::core_types::SaltyOSFramebufferInfoV1;

/// Framebuffer information advertised to the current process.
pub struct FramebufferInfo {
    pub phys_addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub red_pos: u8,
    pub red_size: u8,
    pub green_pos: u8,
    pub green_size: u8,
    pub blue_pos: u8,
    pub blue_size: u8,
}

impl From<SaltyOSFramebufferInfoV1> for FramebufferInfo {
    fn from(raw: SaltyOSFramebufferInfoV1) -> Self {
        Self {
            phys_addr: raw.phys_addr,
            width: raw.width,
            height: raw.height,
            pitch: raw.pitch,
            bpp: raw.bpp,
            red_pos: raw.red_pos,
            red_size: raw.red_size,
            green_pos: raw.green_pos,
            green_size: raw.green_size,
            blue_pos: raw.blue_pos,
            blue_size: raw.blue_size,
        }
    }
}

/// Read framebuffer info from the startup block.
///
/// Returns `None` if no framebuffer record is present or the record
/// carries `phys_addr == 0`.
///
/// # Safety
/// If no startup block is installed, the boot info page must be
/// mapped at `KERNITE_BOOTINFO_VADDR` for the fallback path.
pub unsafe fn read_framebuffer_info() -> Option<FramebufferInfo> {
    if let Some(raw) = crate::runtime_get_framebuffer_info() {
        return Some(FramebufferInfo::from(raw));
    }
    if crate::runtime_has_startup_block() {
        return None;
    }

    let raw: kernite_bootinfo_framebuffer =
        unsafe { bootinfo::read_typed(KERNITE_BOOTINFO_TAG_FRAMEBUFFER as u16)? };
    if raw.phys_addr == 0 {
        return None;
    }
    Some(FramebufferInfo {
        phys_addr: raw.phys_addr,
        width: raw.width,
        height: raw.height,
        pitch: raw.pitch,
        bpp: raw.bpp,
        red_pos: raw.red_pos,
        red_size: raw.red_size,
        green_pos: raw.green_pos,
        green_size: raw.green_size,
        blue_pos: raw.blue_pos,
        blue_size: raw.blue_size,
    })
}
