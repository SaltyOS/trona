// Memory manager server (mmsrv) IPC protocol labels (0x80-0x95, 0x97 range).
// SPDX-License-Identifier: GPL-2.0-only

pub const MM_REGISTER: u64 = 0x80;
pub const MM_DEREGISTER: u64 = 0x81;
pub const MM_BRK: u64 = 0x82;
pub const MM_SBRK: u64 = 0x83;
pub const MM_MMAP: u64 = 0x84;
pub const MM_MUNMAP: u64 = 0x85;
pub const MM_MPROTECT: u64 = 0x86;
pub const MM_MAP_BATCH: u64 = 0x87;
pub const MM_MAP_WINDOW: u64 = 0x88;
pub const MM_UNMAP_WINDOW: u64 = 0x89;
pub const MM_SHM_CREATE: u64 = 0x8A;
pub const MM_SHM_MAP: u64 = 0x8B;
pub const MM_SHM_UNMAP: u64 = 0x8C;
pub const MM_FORK_REGIONS: u64 = 0x8D;
pub const MM_ALLOC_THREAD_OBJECTS: u64 = 0x8E;
pub const MM_FREE_THREAD_OBJECTS: u64 = 0x8F;
pub const MM_GET_CLIENT_STATS: u64 = 0x90;
pub const MM_ALLOC_OBJECT: u64 = 0x91;
pub const MM_REGISTER_SHARED_REGION: u64 = 0x92;
pub const MM_MAP_OBJECT_REGION: u64 = 0x93;
pub const MM_SYNC_FILE_BACKING: u64 = 0x94;
pub const MM_FILE_MMAP: u64 = 0x95;
// 0x96 reserved (device mmap handled as subcase of MM_FILE_MMAP)
pub const MM_SYNC_MMAP_WRITE: u64 = 0x97;
pub const MM_PROVISION_UNTYPED: u64 = 0x98;
pub const MM_QUERY_CAPACITY: u64 = 0x99;
pub const MM_PAGER_REQUEST: u64 = 0x9A;
pub const MM_PAGER_WRITE_REQUEST: u64 = 0x9B;
pub const MM_DUMP_PENDING: u64 = 0x9C;
pub const MM_REGISTER_PAGER_EP: u64 = 0x9D;
pub const MM_ALLOC_PRIVATE_REGION: u64 = 0x9E;
pub const MM_ALLOC_PRIVATE_WINDOW: u64 = 0x9F;
pub const MM_ALLOC_INITRD_COPY: u64 = 0xA0;
pub const MM_ALLOC_BOOTINFO_COPY: u64 = 0xA1;
pub const MM_COPY_FROM_CLIENT_REGION: u64 = 0xA2;
pub const MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION: u64 = 0xA3;
