// SPDX-License-Identifier: GPL-2.0-only
//
//! Spawner runtime — cap_table builder + reader, role IDs, child
//! VM layout planner, stack provisioning. Used exclusively by init
//! during process spawn.

pub mod cap_table;
pub mod layout;
pub mod role_consts;
pub mod stack_consts;
pub mod stack_plan;
