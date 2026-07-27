// SPDX-License-Identifier: GPL-2.0-only
//
//! init server wire (block 0x100..=0x1FF) + supervisor RPC reply
//! payload shapes (`KinfoProc`, system / per-process accounting).
//!
//! Sub-op labels (`INIT_THREAD / INIT_GET_PROC_INFO / ...`) carry
//! their sub-op in `regs[0]`; the `INIT_*_SUB_*` consts below are
//! the sub-op values.

// ---------------------------------------------------------------------------
// init RPC labels.
// ---------------------------------------------------------------------------

pub const INIT_GET_PID: u64 = 0x106;
/// Core-service boot readiness signal. namesrv / rsrcsrv / mmsrv send
/// this on `ROLE_INIT_CONTROL` after their own reactor input has been
/// armed. Init consumes it during the ordered boot pipeline; regular
/// manifest services must use `INIT_NOTIFY_READY` instead.
pub const INIT_CORE_READY: u64 = 0x17F;
/// `Type=notify` leaf service readiness signal. Send-only (no reply);
/// `regs[0] = manifest_idx`. unit_mgr unblocks dependents on receipt.
pub const INIT_NOTIFY_READY: u64 = 0x180;
pub const INIT_THREAD: u64 = 0x150;
pub const INIT_THREAD_SUB_CREATE: u64 = 0x00;
pub const INIT_THREAD_SUB_EXIT: u64 = 0x01;
pub const INIT_THREAD_SUB_JOIN: u64 = 0x02;
pub const INIT_THREAD_SUB_DETACH: u64 = 0x03;
pub const INIT_THREAD_SUB_REAP: u64 = 0x04;
pub const INIT_THREAD_SUB_GET_THREAD_CAPS: u64 = 0x05;
pub const INIT_GET_PROC_INFO: u64 = 0x160;
pub const INIT_GET_PROC_INFO_SUB_GET_PROC_TIMES: u64 = 0x02;
pub const INIT_GET_PROC_INFO_SUB_GET_SYSTEM_STATS: u64 = 0x03;
pub const INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC: u64 = 0x04;
pub const INIT_GET_PROC_INFO_SUB_LIST_PIDS_BUF: u64 = 0x05;
pub const INIT_GET_PROC_INFO_SUB_GET_ARGV: u64 = 0x06;

/// Per-page argv byte count for the paginated `GET_ARGV` transport. An
/// MP record carries only 32 words (256 B), so argv (`ARGV_MAX` = 512 B
/// of NUL-separated strings) is paged: `regs[0]=total`, `regs[1]=written`,
/// `regs[2..]` carry up to this many bytes from the requested offset.
/// Both init (producer) and vfs (page-issuing consumer) key off this.
pub const INIT_ARGV_PAGE_BYTES: usize = 240;
/// Per-process VM stats — init asks mmsrv for the
/// `TronaProcMemSnapshot` belonging to `regs[1]=pid`. Reply
/// places the snapshot in the IPC buffer's `reserved[]` area;
/// `regs[0]` reports the byte size produced.
pub const INIT_GET_PROC_INFO_SUB_GET_CLIENT_VM_STATS: u64 = 0x07;
/// Per-CPU runtime accumulators — init aggregates the kernel's
/// monotonic CPU snapshot. Reply places `TronaSysInfo` followed
/// by up to `cpus.len()` `TronaSysInfoCpu` entries in the IPC
/// buffer's `reserved[]` area; `regs[0]` reports the number of
/// per-CPU entries actually written.
pub const INIT_GET_PROC_INFO_SUB_GET_CPU_INFO: u64 = 0x08;
/// Full per-process bookkeeping — init's `Process` summary for
/// `regs[1]=pid`. Reply: `regs[1]=ppid`, `regs[2]=pgid`,
/// `regs[3]=sid`, `regs[4]=state`, `regs[5..9]` = NUL-padded
/// `name[0..32]`, `regs[9]=start_time_ns`, `regs[10]=tty_dev`,
/// `regs[11]=tty_pgrp`. Used by `/proc/<pid>/{stat,status,cmdline,
/// comm}` formatters.
pub const INIT_GET_PROC_INFO_SUB_GET_PROC_INFO_FULL: u64 = 0x09;
/// Process exe path — init returns the path init / exec stamped
/// onto `regs[1]=pid`. Reply: `regs[0]=path_len`, path bytes
/// follow in `regs[1..]` packed 8 bytes per slot. Used by
/// `/proc/<pid>/exe` symlink resolution.
pub const INIT_GET_PROC_INFO_SUB_GET_EXE_PATH: u64 = 0x0A;
/// Enumerate-by-index process snapshot — init returns the
/// `regs[1]=offset`-th process in its iteration order, so a consumer
/// can page through every process without first listing pids. Reply:
/// `regs[0]=total` (process count), `regs[1]=1` if a record was
/// written for this offset (`0` once `offset >= total`), and the
/// `KinfoProc` bytes packed into `regs[2..]` (`INIT_KINFO_PROC_REGS_BASE`).
/// init fills only the fields it owns (identity / lifecycle / cred /
/// times); `vm_size` / `vm_rss` / `tty_dev` are left zero for the
/// consumer (vfs) to enrich from mmsrv / pty. Backs `kern.proc.all`
/// and the `kern.proc.{pgrp,tty,uid,ruid,session}` filter dirs, which
/// page through and filter locally.
pub const INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC_PAGE: u64 = 0x0B;
/// First `regs` slot carrying `KinfoProc` bytes in a `GET_KINFO_PROC`
/// / `GET_KINFO_PROC_PAGE` reply (`regs[0]`/`regs[1]` are the
/// total/present words for the page variant).
pub const INIT_KINFO_PROC_REGS_BASE: usize = 2;
/// `KinfoProc` records carried per `GET_KINFO_PROC_PAGE` reply. One
/// `KinfoProc` (136 B) fits in `regs[2..]` (30 words = 240 B) but two
/// do not; a future bulk (shared-frame) transport can raise this
/// without changing the consumer's page-accumulate loop.
pub const INIT_KINFO_PROC_PER_PAGE: usize = 1;

// ---------------------------------------------------------------------------
// FreeBSD-style kinfo_proc — process snapshot wire shape.
//
// Returned by init server's `INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC` reply.
// ABI rule: fields may only be appended; `size` reports the producer's
// `sizeof(KinfoProc)` so consumers can refuse to read past it.
// ---------------------------------------------------------------------------

/// Length of the `comm` (process name) field. Matches the init
/// server's `Process.name` buffer size.
pub const KINFO_PROC_COMM_LEN: usize = 32;

/// Process snapshot, produced by init and returned through
/// `sysctlfs` `kern.proc.{all,pid/<pid>,pgrp/<pgid>,...}`.
///
/// All runtime fields are nanoseconds.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KinfoProc {
    /// `sizeof(Self)` as produced. Read this first.
    pub size: u32,
    pub _pad0: u32,
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    /// Foreground process-group id of the controlling terminal, or 0.
    pub tpgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    /// Device id of the controlling terminal (`Process.ctty_dev`).
    pub tty_dev: u32,
    /// `ProcessState` discriminant from init.
    pub state: u8,
    pub nice: i8,
    pub _pad1: [u8; 6],
    /// User-mode runtime accumulated across all threads of the
    /// process (live threads + exited-thread carry-over), in
    /// nanoseconds.
    pub user_time_ns: u64,
    /// Kernel-mode runtime accumulated across all threads (ns).
    pub system_time_ns: u64,
    /// Kernel monotonic-clock timestamp at process creation (ns).
    pub start_time_ns: u64,
    /// Total mapped bytes (heap + regions).
    pub vm_size: u64,
    /// Resident bytes, derived from the per-process memory snapshot.
    pub vm_rss: u64,
    pub num_threads: u32,
    pub _pad2: u32,
    /// Short process name, NUL-padded.
    pub comm: [u8; KINFO_PROC_COMM_LEN],
}

impl KinfoProc {
    pub const fn zeroed() -> Self {
        KinfoProc {
            size: 0,
            _pad0: 0,
            pid: 0,
            ppid: 0,
            pgid: 0,
            sid: 0,
            tpgid: 0,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            tty_dev: 0,
            state: 0,
            nice: 0,
            _pad1: [0; 6],
            user_time_ns: 0,
            system_time_ns: 0,
            start_time_ns: 0,
            vm_size: 0,
            vm_rss: 0,
            num_threads: 0,
            _pad2: 0,
            comm: [0; KINFO_PROC_COMM_LEN],
        }
    }
}

// ---------------------------------------------------------------------------
// System + per-CPU accounting (returned by `INIT_GET_PROC_INFO_SUB_GET_CPU_INFO`).
// ---------------------------------------------------------------------------

/// Header describing overall system state. The init server fills this
/// before each per-CPU array entry.
///
/// Time fields are kernel monotonic-clock values in nanoseconds:
/// `uptime_ns` is time since boot; `boot_time_ns` is the wall-clock
/// timestamp at which the kernel recorded boot.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaSysInfo {
    pub uptime_ns: u64,
    pub boot_time_ns: u64,
    pub cpu_count: u32,
    pub cpus_written: u32,
    pub context_switches_total: u64,
}

impl TronaSysInfo {
    pub const fn zeroed() -> Self {
        TronaSysInfo {
            uptime_ns: 0,
            boot_time_ns: 0,
            cpu_count: 0,
            cpus_written: 0,
            context_switches_total: 0,
        }
    }
}

/// Per-CPU runtime accumulators. All counters are in nanoseconds.
/// The trailing `_reserved` word lets future kernels append counters
/// (irq / softirq / steal) without breaking ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TronaSysInfoCpu {
    pub idle_time_ns: u64,
    pub user_time_ns: u64,
    pub system_time_ns: u64,
    pub _reserved: u64,
}

impl TronaSysInfoCpu {
    pub const fn zeroed() -> Self {
        TronaSysInfoCpu {
            idle_time_ns: 0,
            user_time_ns: 0,
            system_time_ns: 0,
            _reserved: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PMM-wide memory accounting snapshot (returned by `MM_GET_SYSTEM_MEMINFO`).
// Lives here because the wire shape is shared between init's procfs /
// sysctlfs projections and mmsrv's reply payload.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TronaSysMemInfo {
    pub pages_total: u64,
    pub pages_free: u64,
    pub pages_untyped_reserved: u64,
    pub pages_mo_data: u64,
    pub pages_mo_meta: u64,
    pub pages_page_cache: u64,
    pub pages_anon_private: u64,
    pub pages_anon_shared: u64,
    pub pages_file: u64,
    pub pages_kernel_pagetable: u64,
    pub pages_kernel_stack: u64,
    pub pages_kernel_slab: u64,
    pub pages_emergency_reserve: u64,
    pub pages_dirty_file: u64,
    pub pages_writeback_file: u64,
    pub pages_active: u64,
    pub pages_inactive: u64,
    pub page_size: u64,
    pub snapshot_ns: u64,
    pub reserved: [u64; 1],
}

impl TronaSysMemInfo {
    pub const fn zeroed() -> Self {
        Self {
            pages_total: 0,
            pages_free: 0,
            pages_untyped_reserved: 0,
            pages_mo_data: 0,
            pages_mo_meta: 0,
            pages_page_cache: 0,
            pages_anon_private: 0,
            pages_anon_shared: 0,
            pages_file: 0,
            pages_kernel_pagetable: 0,
            pages_kernel_stack: 0,
            pages_kernel_slab: 0,
            pages_emergency_reserve: 0,
            pages_dirty_file: 0,
            pages_writeback_file: 0,
            pages_active: 0,
            pages_inactive: 0,
            page_size: 4096,
            snapshot_ns: 0,
            reserved: [0; 1],
        }
    }
}

// ---------------------------------------------------------------------------
// Per-VSpace memory accounting (returned by `KERNITE_INV_VSPACE_GET_MEM_STATS`).
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TronaVSpaceMemStats {
    pub vm_reserved_bytes: u64,
    pub vm_resident_pages: u64,
    pub vm_demand_pages: u64,
    pub vm_cow_pages: u64,
    pub vm_shared_pages: u64,
    pub vm_pt_pages: u64,
    pub vm_kstack_pages: u64,
    pub resident_anon: u64,
    pub resident_file: u64,
    pub resident_shm: u64,
    pub vm_stk_bytes: u64,
    pub vm_exe_bytes: u64,
    pub vm_data_bytes: u64,
    pub vm_lib_bytes: u64,
    pub vm_peak_reserved_bytes: u64,
    pub vm_peak_resident_pages: u64,
}

/// Per-range resident-memory summary for a VSpace. Returned by
/// `KERNITE_INV_VSPACE_GET_RANGE_STATS`. `pss_bytes` is byte-precise
/// so userland formatters can round once after summing per-page
/// shares.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TronaVSpaceRangeStats {
    pub present_pages: u64,
    pub referenced_pages: u64,
    pub shared_pages: u64,
    pub shared_dirty_pages: u64,
    pub private_dirty_pages: u64,
    pub writeback_pages: u64,
    pub pss_bytes: u64,
}

impl TronaVSpaceRangeStats {
    pub const fn zeroed() -> Self {
        Self {
            present_pages: 0,
            referenced_pages: 0,
            shared_pages: 0,
            shared_dirty_pages: 0,
            private_dirty_pages: 0,
            writeback_pages: 0,
            pss_bytes: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-process memory snapshot — projection that glues kernel-owned
// VSPACE stats to mmsrv-owned heap and region metadata. Returned via
// init's `INIT_GET_CLIENT_VM_STATS` and produced by mmsrv.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TronaProcMemSnapshot {
    pub vm_reserved_bytes: u64,
    pub vm_resident_pages: u64,
    pub vm_demand_pages: u64,
    pub vm_cow_pages: u64,
    pub vm_shared_pages: u64,
    pub vm_pt_pages: u64,
    pub vm_kstack_pages: u64,
    pub resident_anon: u64,
    pub resident_file: u64,
    pub resident_shm: u64,
    pub vm_stk_bytes: u64,
    pub vm_exe_bytes: u64,
    pub vm_data_bytes: u64,
    pub vm_lib_bytes: u64,
    pub heap_base: u64,
    pub heap_current: u64,
    pub region_count: u64,
    pub file_backed_dirty_pages: u64,
    pub vm_peak_reserved_bytes: u64,
    pub vm_peak_resident_pages: u64,
}

impl TronaProcMemSnapshot {
    pub const fn zeroed() -> Self {
        Self {
            vm_reserved_bytes: 0,
            vm_resident_pages: 0,
            vm_demand_pages: 0,
            vm_cow_pages: 0,
            vm_shared_pages: 0,
            vm_pt_pages: 0,
            vm_kstack_pages: 0,
            resident_anon: 0,
            resident_file: 0,
            resident_shm: 0,
            vm_stk_bytes: 0,
            vm_exe_bytes: 0,
            vm_data_bytes: 0,
            vm_lib_bytes: 0,
            heap_base: 0,
            heap_current: 0,
            region_count: 0,
            file_backed_dirty_pages: 0,
            vm_peak_reserved_bytes: 0,
            vm_peak_resident_pages: 0,
        }
    }
}
