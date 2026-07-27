// SPDX-License-Identifier: GPL-2.0-only
//
//! pcidrv service wire labels.

pub const PCI_FIND_DEVICE: u64 = 1;
pub const PCI_GET_CAPS: u64 = 2;
pub const PCI_LIST: u64 = 3;
pub const PCI_READ_CONFIG32: u64 = 4;
pub const PCI_GET_BAR_CAP: u64 = 5;
pub const PCI_WRITE_CONFIG32: u64 = 6;
