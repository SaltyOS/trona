// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX mmap ABI constants — `PROT_*` / `MAP_*`.

// PROT_* flags
pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;

// MAP_* flags
pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANONYMOUS: i32 = 0x20;
pub const MAP_LAZY: i32 = 0x40;
/// Treat the mapping as a thread/user stack. mmsrv classifies the
/// resulting region as `REGION_STACK` so procfs/sysctlfs surface the
/// correct `VmStk` figure.
pub const MAP_STACK: i32 = 0x20000;
/// `MAP_FIXED` variant that fails (with `EEXIST`) if the requested
/// range already overlaps an existing mapping or reservation.
/// Linux-compatible value — userland code that imports the libc
/// constant needs no translation.
pub const MAP_FIXED_NOREPLACE: i32 = 0x100000;

// MS_* flags
pub const MS_ASYNC: i32 = 0x1;
pub const MS_INVALIDATE: i32 = 0x2;
pub const MS_SYNC: i32 = 0x4;
