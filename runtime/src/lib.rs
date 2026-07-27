//! trona_runtime — SaltyOS userspace process runtime.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Five internal namespaces:
//!
//! - **`core`** — slot allocator (`slot_alloc`, `slot_pool`), IPC
//!   convenience wrappers (`ipc_ext`, `ipc_timer`), runtime policy
//!   constants (`server_consts`).
//! - **`client`** — well-known cap getters (`caps`), lazy service
//!   lookup (`lazy_resolve`), VFS / mmsrv client wrappers
//!   (`vfs`, `mm`).
//! - **`spawn`** — child process bootstrap state used by init:
//!   cap-table builder + reader (`cap_table`), role IDs
//!   (`role_consts`), VM layout planner (`layout`), stack
//!   provisioning (`stack_plan`, `stack_consts`).
//! - **`thread`** — TLS (`tls`), thread spawn (`thread`),
//!   per-worker bookkeeping (`worker`), futex / sync primitives
//!   (`sync`).
//! - **`debug`** — early-boot console (`serial`), framebuffer
//!   info reader (`framebuffer`).
//!
//! Kernel ABI primitives live in `trona_kernel`; cross-server wire
//! constants and reply payload shapes live in `trona_protocol`;
//! server-loop primitives live in `trona_server`.
//!
//! # C ABI exports
//!
//! Every `trona_*` function in this file is `#[unsafe(no_mangle)] pub extern "C"`
//! so that the runtime dynamic linker (`rtld`) can resolve them
//! from `libtrona.so`. C programs link against these symbols via
//! `saltyc`.
//!
//! # Global state
//!
//! - [`__trona_ipc_ctx`] — per-process IPC context (IPC buffer
//!   pointer + send-cap counter). Initialized by `rtld` (dynamic)
//!   or the CRT (static) before `main`.
//! - `__trona_next_free_slot` — weak symbol overridden by `rtld`
//!   with the first post-startup free slot after reserving its
//!   own frame, library-MO, and slot-allocator capabilities.

#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(linkage)]

extern crate core as rust_core;

use rust_core::cmp;
use rust_core::fmt::{Result as FmtResult, Write};

pub mod abi;
pub mod client;
pub mod core;
pub mod debug;
mod panic;
pub mod spawn;
pub mod thread;
pub mod weak;

// Re-export every weak / strong symbol rtld and the CRT bind so
// downstream code (and the rest of this lib.rs) can keep referring
// to `crate::__trona_*` directly.
pub use weak::*;

use crate::core::slot_alloc;
use crate::debug::serial;
use crate::spawn::cap_table;
use trona_kernel::core_types::{
    AT_SALTYOS_STARTUP, Cap, IpcContext, RtldDlfcnV1, SaltyOSCapTableV1, SaltyOSCspaceLayoutV1,
    SaltyOSFramebufferInfoV1, SaltyOSStartupLayoutV1, TronaLoaderRuntimeV1, TronaMsg,
    TronaRuntimeV1,
};
use trona_kernel::ipc;
use trona_protocol::init::KinfoProc;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Per-process IPC context holding the IPC buffer pointer and send-cap count.

// ---------------------------------------------------------------------------
// IPC context accessor (weak -- overridden by TLS-aware version in trona_posix)
// ---------------------------------------------------------------------------

/// Return the current thread's IPC context.
///
/// If TLS is active (THREAD_LOCAL_ACTIVE is set), returns the per-thread
/// IPC context from the thread-local block. Otherwise falls back to the
/// global `__trona_ipc_ctx`.
#[inline]
pub fn current_ipc_ctx() -> *mut IpcContext {
    crate::thread::tls::current_ipc_ctx()
}

unsafe fn runtime_find_auxv_value(auxv: *const u64, wanted: u64) -> u64 {
    unsafe {
        if auxv.is_null() {
            return 0;
        }
        let mut p = auxv;
        while !p.is_null() {
            let tag = *p;
            let val = *p.add(1);
            if tag == 0 {
                break;
            }
            if tag == wanted {
                return val;
            }
            p = p.add(2);
        }
        0
    }
}

#[inline]
unsafe fn runtime_ptr() -> *const TronaRuntimeV1 {
    &raw const __trona_runtime
}

pub(crate) unsafe fn runtime_get_installed() -> Option<&'static TronaRuntimeV1> {
    let rt = unsafe { &*runtime_ptr() };
    if rt.is_valid() { Some(rt) } else { None }
}

pub(crate) unsafe fn runtime_resolve_startup_from_auxv(
    auxv: *const u64,
) -> Option<&'static SaltyOSStartupLayoutV1> {
    let ptr = unsafe { runtime_find_auxv_value(auxv, AT_SALTYOS_STARTUP) };
    if ptr == 0 {
        return None;
    }

    let startup = unsafe { &*(ptr as *const SaltyOSStartupLayoutV1) };
    if startup.is_valid() {
        Some(startup)
    } else {
        None
    }
}

unsafe fn runtime_resolve_cspace_layout_from_auxv(
    auxv: *const u64,
) -> Option<*const SaltyOSCspaceLayoutV1> {
    unsafe {
        let startup = runtime_resolve_startup_from_auxv(auxv)?;
        if startup.cspace_layout_ptr == 0 {
            return None;
        }
        let layout = startup.cspace_layout_ptr as *const SaltyOSCspaceLayoutV1;
        if !layout.is_null() && (*layout).version == SaltyOSCspaceLayoutV1::VERSION {
            Some(layout)
        } else {
            None
        }
    }
}

unsafe fn runtime_resolve_bootstrap_untyped_from_auxv(auxv: *const u64) -> u64 {
    unsafe {
        match runtime_resolve_cspace_layout_from_auxv(auxv) {
            Some(layout) => (*layout).rtld_untyped_base,
            None => 0,
        }
    }
}

unsafe fn runtime_resolve_slot_pool_from_auxv(auxv: *const u64) -> (u64, u64) {
    unsafe {
        let mut slot_base = 0u64;
        let mut slot_count = 0u64;

        if let Some(layout) = runtime_resolve_cspace_layout_from_auxv(auxv) {
            let frame_floor = cmp::max(__trona_next_free_slot, (*layout).frame_slot_base);
            if let Some((base, count)) = runtime_slot_pool_range(&*layout, frame_floor) {
                slot_base = base;
                slot_count = count;
            }
        }

        (slot_base, slot_count)
    }
}

fn runtime_slot_pool_range(layout: &SaltyOSCspaceLayoutV1, frame_floor: u64) -> Option<(u64, u64)> {
    let floor = cmp::max(frame_floor, layout.frame_slot_base);
    let mut base = cmp::max(layout.alloc_base, floor);
    let alloc_limit = layout.alloc_limit;

    loop {
        let mut advanced = false;
        if layout.has_expand_range() && base >= layout.expand_base && base < layout.expand_limit {
            base = layout.expand_limit;
            advanced = true;
        }
        if layout.has_recv_range() && base >= layout.recv_base && base < layout.recv_limit {
            base = layout.recv_limit;
            advanced = true;
        }
        if !advanced {
            break;
        }
    }

    let mut limit = alloc_limit;
    if layout.has_expand_range() && layout.expand_base > base && layout.expand_base < limit {
        limit = layout.expand_base;
    }
    if layout.has_recv_range() && layout.recv_base > base && layout.recv_base < limit {
        limit = layout.recv_base;
    }

    if base < limit {
        Some((base, limit - base))
    } else {
        None
    }
}

pub unsafe fn runtime_install(runtime: *const TronaRuntimeV1) {
    unsafe {
        if runtime.is_null() {
            return;
        }
        let rt = &*runtime;
        if !rt.is_valid() {
            return;
        }
        __trona_runtime = *rt;
        __trona_saved_auxv = rt.auxv_ptr as *const u64;
        __trona_next_free_slot = rt.next_free_slot;
        __trona_sc_cap = rt.sc_cap;
        __trona_tls_template = rt.tls_template;
        __trona_tls_filesz = rt.tls_filesz;
        __trona_tls_memsz = rt.tls_memsz;
        __trona_tls_align = rt.tls_align;
        __trona_tls_module_count = rt.tls_module_count;
        __trona_tls_modules = rt.tls_modules;
        let _ = cap_table::install_well_known_caps(rt.cap_table_ptr as *const SaltyOSCapTableV1);
    }
}

// Loader runtime — published by rtld via `trona_loader_runtime_install`.
// libtrona only stores the pointer; the rtld owns the storage.
static LOADER_RUNTIME: ::core::sync::atomic::AtomicPtr<TronaLoaderRuntimeV1> =
    ::core::sync::atomic::AtomicPtr::new(::core::ptr::null_mut());

/// Bit set of every `TronaLoaderRuntimeV1::flags` value this libtrona
/// knows about. New flag bits MUST be added here in lockstep with
/// `TronaLoaderRuntimeV1` in `core_types.rs`; the install path rejects
/// descriptors that carry bits outside this mask so a forward-only
/// rtld cannot smuggle behaviour past an older libtrona.
const KNOWN_LOADER_FLAGS: u64 = 0;

/// Install the rtld-published loader runtime. Returns 0 on success and a
/// negative error code on failure.
///
/// # Safety
/// `runtime` must point to a `TronaLoaderRuntimeV1` whose lifetime exceeds
/// every subsequent dlfcn call. The rtld holds it as a process-lifetime
/// static, satisfying that requirement.
pub unsafe fn loader_runtime_install(runtime: *const TronaLoaderRuntimeV1) -> i32 {
    if runtime.is_null() {
        return -1;
    }
    let rt = unsafe { &*runtime };
    if !rt.is_valid() {
        return -1;
    }
    if rt.flags & !KNOWN_LOADER_FLAGS != 0 {
        return -2;
    }
    LOADER_RUNTIME.store(
        runtime as *mut TronaLoaderRuntimeV1,
        ::core::sync::atomic::Ordering::Release,
    );
    0
}

/// Look up the installed loader runtime, if any. Returns `None` until the
/// rtld has called `trona_loader_runtime_install`.
pub fn loader_runtime() -> Option<&'static TronaLoaderRuntimeV1> {
    let p = LOADER_RUNTIME.load(::core::sync::atomic::Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    let rt = unsafe { &*p };
    if rt.is_valid() { Some(rt) } else { None }
}

/// Convenience accessor for the rtld dlfcn function table.
pub fn loader_dlfcn() -> Option<&'static RtldDlfcnV1> {
    loader_runtime().map(|rt| &rt.dlfcn)
}

pub unsafe fn runtime_set_auxv(auxv: *const u64) {
    unsafe {
        __trona_saved_auxv = auxv;
        let _ = cap_table::runtime_install_from_auxv(auxv);
    }
}

pub fn runtime_get_ipc_buffer_vaddr() -> Option<u64> {
    unsafe {
        let auxv = __trona_saved_auxv;
        let startup = runtime_resolve_startup_from_auxv(auxv)?;
        (startup.ipc_buffer_vaddr != 0).then_some(startup.ipc_buffer_vaddr)
    }
}

pub fn runtime_get_boot_untyped_stats() -> Option<(u64, u64, u64, u64)> {
    unsafe {
        let auxv = __trona_saved_auxv;
        let startup = runtime_resolve_startup_from_auxv(auxv)?;
        if startup.boot_untyped_slot == 0 || startup.boot_untyped_size_bits == 0 {
            return None;
        }
        Some((
            startup.boot_untyped_slot,
            startup.boot_untyped_size_bits,
            startup.boot_untyped_size_bytes,
            startup.boot_untyped_available_bytes,
        ))
    }
}

pub fn runtime_get_framebuffer_info() -> Option<SaltyOSFramebufferInfoV1> {
    unsafe {
        if let Some(rt) = runtime_get_installed() {
            let ptr = rt.startup_ptr as *const SaltyOSStartupLayoutV1;
            if !ptr.is_null() {
                let startup = &*ptr;
                if startup.is_valid() && startup.framebuffer.is_present() {
                    return Some(startup.framebuffer);
                }
            }
        }

        let auxv = __trona_saved_auxv;
        let startup = runtime_resolve_startup_from_auxv(auxv)?;
        startup
            .framebuffer
            .is_present()
            .then_some(startup.framebuffer)
    }
}

pub fn runtime_has_startup_block() -> bool {
    unsafe {
        if let Some(rt) = runtime_get_installed() {
            let ptr = rt.startup_ptr as *const SaltyOSStartupLayoutV1;
            if !ptr.is_null() && (*ptr).is_valid() {
                return true;
            }
        }

        runtime_resolve_startup_from_auxv(__trona_saved_auxv).is_some()
    }
}

pub fn runtime_get_cspace_layout() -> Option<SaltyOSCspaceLayoutV1> {
    unsafe {
        if let Some(rt) = runtime_get_installed() {
            let ptr = rt.cspace_layout_ptr as *const SaltyOSCspaceLayoutV1;
            if !ptr.is_null() && (*ptr).version == SaltyOSCspaceLayoutV1::VERSION {
                return Some(*ptr);
            }
        }
        let auxv = __trona_saved_auxv;
        let layout = runtime_resolve_cspace_layout_from_auxv(auxv)?;
        Some(*layout)
    }
}

pub fn runtime_get_bootstrap_untyped() -> Option<Cap> {
    unsafe {
        let auxv = __trona_saved_auxv;
        if auxv.is_null() {
            return None;
        }
        match runtime_resolve_bootstrap_untyped_from_auxv(auxv) {
            0 => None,
            cap => Some(cap),
        }
    }
}

/// Return a legacy single contiguous slot pool for callers that do not
/// understand multi-segment CSpace layouts.
pub fn runtime_get_slot_pool() -> Option<(u64, u64)> {
    unsafe {
        if let Some(layout) = runtime_get_cspace_layout() {
            let frame_floor = if let Some(rt) = runtime_get_installed() {
                rt.next_free_slot
            } else {
                __trona_next_free_slot
            };
            if let Some((base, count)) = runtime_slot_pool_range(&layout, frame_floor) {
                return Some((base, count));
            }
        }
        let auxv = __trona_saved_auxv;
        let (slot_base, slot_count) = if !auxv.is_null() {
            runtime_resolve_slot_pool_from_auxv(auxv)
        } else {
            (0, 0)
        };
        (slot_base != 0 && slot_count != 0).then_some((slot_base, slot_count))
    }
}

/// Initialize the process slot allocator from the installed startup CSpace
/// layout, preserving all usable segments while subtracting reserved holes.
///
/// # Safety
/// Must be called during process startup before concurrent slot allocation.
pub unsafe fn runtime_init_slot_allocator() -> bool {
    unsafe {
        let Some(layout) = runtime_get_cspace_layout() else {
            return false;
        };
        let frame_floor = if let Some(rt) = runtime_get_installed() {
            rt.next_free_slot
        } else {
            __trona_next_free_slot
        };
        if !slot_alloc::slot_alloc_init_from_layout(&layout, frame_floor) {
            return false;
        }

        // Reserve `expand_temp_slot` from the existing flat segment via
        // the no-expand path so the reservation itself never recurses
        // into self-expansion. Failure is non-fatal — the process simply
        // runs without self-expand. We do NOT resolve the rsrcsrv send
        // here: doing so would issue `NAMESRV_LOOKUP("rsrcsrv")` against
        // namesrv during CRT bootstrap, which deadlocks rsrcsrv against
        // itself (rsrcsrv has not yet reached `register_with_namesrv`
        // when its own CRT runs). Instead, the substrate's first
        // `slot_alloc::alloc_object` (or a process-specific carve-out
        // handler in rsrcsrv's case) does the lazy resolve at use time.
        if layout.has_expand_range() {
            if let Some(temp) = slot_alloc::slot_alloc_no_expand() {
                crate::core::slot_alloc::reserve_expand_temp_slot(temp);
            }
        }
        true
    }
}

pub fn runtime_slot_allocator_matches_layout() -> bool {
    unsafe {
        let Some(layout) = runtime_get_cspace_layout() else {
            return false;
        };
        let frame_floor = if let Some(rt) = runtime_get_installed() {
            rt.next_free_slot
        } else {
            __trona_next_free_slot
        };
        crate::core::slot_alloc::slot_alloc_matches_layout(&layout, frame_floor)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trona_runtime_set_auxv(auxv: *const u64) {
    unsafe { runtime_set_auxv(auxv) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trona_runtime_install(runtime: *const TronaRuntimeV1) {
    unsafe { runtime_install(runtime) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trona_loader_runtime_install(runtime: *const TronaLoaderRuntimeV1) -> i32 {
    unsafe { loader_runtime_install(runtime) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trona_runtime_get_slot_pool(
    base_out: *mut u64,
    count_out: *mut u64,
) -> i32 {
    unsafe {
        if base_out.is_null() || count_out.is_null() {
            return -1;
        }
        let Some((base, count)) = runtime_get_slot_pool() else {
            return -1;
        };
        *base_out = base;
        *count_out = count;
        0
    }
}

// ---------------------------------------------------------------------------
// Panic handler (for libtrona.so and statically-linked binaries)
// ---------------------------------------------------------------------------

struct SerialFmtWriter<'a> {
    line: &'a mut serial::LineBuf,
}

impl Write for SerialFmtWriter<'_> {
    fn write_str(&mut self, s: &str) -> FmtResult {
        self.line.str(s.as_bytes());
        Ok(())
    }
}

/// Send the `Type=notify` readiness signal to init. Leaf services
/// (e.g. posix_getty) call this once they have completed their own
/// initialization; init's unit_mgr unblocks dependents on receipt.
/// Send-only — init does not reply, so a tx error here is best-effort.
/// Init resolves the caller's manifest entry from the per-client MP
/// the call arrived on (caller_pid → ProcessRecord.name → manifest);
/// the wire carries no service identifier, so a child cannot misroute
/// readiness to a sibling service.
pub fn init_notify_ready() {
    let ep = crate::client::caps::init_ep().addr();
    if ep == 0 {
        return;
    }
    unsafe {
        let mut msg = TronaMsg::zeroed();
        msg.label = trona_protocol::init::INIT_NOTIFY_READY;
        msg.length = 0;
        let _ = ipc::mp_write_ctx(current_ipc_ctx(), ep, &raw const msg);
    }
}

fn panic_getpid() -> Option<u64> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona_protocol::init::INIT_GET_PID;
        msg.length = 0;

        let err = ipc::mp_call_ctx(
            current_ipc_ctx(),
            crate::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != trona_protocol::common::TRONA_OK {
            return None;
        }

        Some(reply.regs[0])
    }
}

// ---------------------------------------------------------------------------
// Rust client wrappers: init supervisor stats
// ---------------------------------------------------------------------------

/// Sum per-thread CPU runtime for `pid`.
///
/// Returns `(user_time_ns, system_time_ns, num_threads, start_time_ns)` or
/// `None` if the process is not found or init is unreachable.
pub fn init_get_proc_times(pid: u32) -> Option<(u64, u64, u64, u64)> {
    let ep = crate::client::caps::init_ep().addr();
    if ep == 0 {
        return None;
    }
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_PROC_TIMES;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::mp_call_ctx(
            current_ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != trona_protocol::common::TRONA_OK {
            return None;
        }
        Some((reply.regs[0], reply.regs[1], reply.regs[2], reply.regs[3]))
    }
}

/// Aggregate process-table counts for `/proc/stat`.
///
/// Returns `(procs_total, procs_running, last_pid)` or `None` on error.
pub fn init_get_system_stats() -> Option<(u64, u64, u64)> {
    let ep = crate::client::caps::init_ep().addr();
    if ep == 0 {
        return None;
    }
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_SYSTEM_STATS;
        msg.length = 0;
        let err = ipc::mp_call_ctx(
            current_ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != trona_protocol::common::TRONA_OK {
            return None;
        }
        Some((reply.regs[0], reply.regs[1], reply.regs[2]))
    }
}

/// Populate `out` with a `KinfoProc` snapshot for `pid`.
///
/// Returns `true` on success. The IPC buffer reserved area is used as the
/// transport; the caller's IPC context must be live when this is called.
pub fn init_get_kinfo_proc(pid: u32, out: &mut KinfoProc) -> bool {
    let ep = crate::client::caps::init_ep().addr();
    if ep == 0 {
        return false;
    }
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_KINFO_PROC;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::mp_call_ctx(
            current_ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != trona_protocol::common::TRONA_OK {
            return false;
        }
        let ctx = &*current_ipc_ctx();
        if ctx.ipc_buffer.is_null() {
            return false;
        }
        let src = (*ctx.ipc_buffer).reserved.as_ptr() as *const KinfoProc;
        *out = ::core::ptr::read(src);
        true
    }
}

/// Paginated PID listing for `pid`.
///
/// Reads up to `out.len()` PIDs starting at `offset` from init's table.
/// Returns `(count_returned, total_processes)` or `None` on error.
pub fn init_list_pids_buf(offset: usize, out: &mut [u32]) -> Option<(usize, usize)> {
    let ep = crate::client::caps::init_ep().addr();
    if ep == 0 {
        return None;
    }
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona_protocol::init::INIT_GET_PROC_INFO_SUB_LIST_PIDS_BUF;
        msg.length = 2;
        msg.regs[0] = offset as u64;
        msg.regs[1] = out.len() as u64;
        let err = ipc::mp_call_ctx(
            current_ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != trona_protocol::common::TRONA_OK {
            return None;
        }
        let count = reply.regs[0] as usize;
        let total = reply.regs[1] as usize;
        let ctx = &*current_ipc_ctx();
        if ctx.ipc_buffer.is_null() {
            return None;
        }
        let src = (*ctx.ipc_buffer).reserved.as_ptr() as *const u32;
        let copy = count.min(out.len());
        for i in 0..copy {
            out[i] = *src.add(i);
        }
        Some((count, total))
    }
}

/// Return the NUL-separated argv of `pid` into `out`.
///
/// Returns the number of bytes written, or `None` if the process is not found.
pub fn init_get_argv(pid: u32, out: &mut [u8]) -> Option<usize> {
    let ep = crate::client::caps::init_ep().addr();
    if ep == 0 {
        return None;
    }
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_ARGV;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::mp_call_ctx(
            current_ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != trona_protocol::common::TRONA_OK {
            return None;
        }
        let argv_len = reply.regs[0] as usize;
        let ctx = &*current_ipc_ctx();
        if ctx.ipc_buffer.is_null() {
            return None;
        }
        let src = (*ctx.ipc_buffer).reserved.as_ptr() as *const u8;
        let copy = argv_len.min(out.len());
        for i in 0..copy {
            out[i] = *src.add(i);
        }
        Some(copy)
    }
}
