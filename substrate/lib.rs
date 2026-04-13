//! trona -- SaltyOS userspace system library (substrate crate)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! The substrate crate provides the core kernel ABI layer:
//!
//! - **`syscall`** -- Raw inline-assembly syscall wrappers
//! - **`ipc`** -- IPC operations (send, recv, call, reply_recv)
//! - **`invoke`** -- Typed capability invocation helpers
//! - **`consts`** -- Syscall numbers, invoke labels, error codes, well-known caps
//! - **`protocol`** -- IPC protocol labels grouped by service/personality
//! - **`types`** -- Shared `#[repr(C)]` types for the Rust/C boundary
//! - **`serial`** -- Diagnostic serial output and log macros
//! - **`slot_alloc`** -- Dynamic CNode slot allocator
//! - **`framebuffer`** -- Framebuffer info reader
//! - **`layout`** -- Child process VA layout planner
//!
//! # C ABI exports
//!
//! Every `trona_*` function in this file is `#[unsafe(no_mangle)] pub extern "C"`
//! so that the runtime dynamic linker (`rtld`) can resolve them from `libtrona.so`.
//! C programs link against these symbols via `saltyc`.
//!
//! # Global state
//!
//! - [`__trona_ipc_ctx`] -- Per-process IPC context (IPC buffer pointer +
//!   send-cap counter). Initialized by `rtld` or the CRT before `main`.
//! - `__trona_next_frame_slot` -- Weak symbol overridden by `rtld` with the
//!   next free frame-allocation slot after startup relocation/loading.

#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(linkage)]

use ::core::fmt::{self, Write};

pub mod cap_table;
pub mod caps;
pub mod casefold;
pub mod casefold_table;
pub mod consts;
pub mod framebuffer;
pub mod invoke;
pub mod ipc;
pub mod layout;
pub mod pending;
pub mod protocol;
pub mod serial;
pub mod slot_alloc;
pub mod sync;
pub mod syscall;
pub mod tls;
pub mod types;
pub mod worker;

// Re-export for convenience
pub use consts::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Per-process IPC context holding the IPC buffer pointer and send-cap count.
/// Initialized by `rtld` (dynamic) or the CRT (static) before `main`.
#[unsafe(no_mangle)]
pub static mut __trona_ipc_ctx: IpcContext = IpcContext::new();

/// Next available CNode slot for frame allocation. Weak symbol overridden
/// by `rtld` with the first post-startup free frame-allocation slot.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_next_frame_slot: u64 = 64;

/// Notification cap for CSpace expansion signaling
/// (from `AT_TRONA_CSPACE_NTFN` auxv). 0 if not available.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cspace_ntfn: u64 = 0;

/// SchedContext capability slot for the main thread
/// (from `AT_TRONA_SC_CAP` auxv). 0 if not provided.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_sc_cap: u64 = 0;

// ---------------------------------------------------------------------------
// Well-known capability slots passed by the spawner via `AT_TRONA_*` auxv.
//
// Each slot lives in the child cspace at a position chosen by the spawner.
// rtld walks the auxv and writes the actual slot number into the matching
// weak symbol below; lib code reads it through the safe `caps::*` getters.
// A value of 0 means the spawner did not provide that capability for this
// process — callers must tolerate that (or fail loudly when the cap is
// strictly required).
// ---------------------------------------------------------------------------

/// Memory manager server IPC endpoint (`ROLE_MMSRV_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_mmsrv_ep: u64 = 0;

/// Process manager IPC endpoint (`ROLE_PROCMGR_CONTROL`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_procmgr_ep: u64 = 0;

/// VFS server IPC endpoint (`ROLE_VFS_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_vfs_ep: u64 = 0;

/// Name service IPC endpoint (`ROLE_NAMESRV_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_namesrv_ep: u64 = 0;

/// Per-thread POSIX signal notification (`ROLE_SIGNAL_NTFN`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_signal_ntfn: u64 = 0;

/// Resource server IPC endpoint (`ROLE_RSRCSRV_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_rsrcsrv_ep: u64 = 0;

/// Console server IPC endpoint (`ROLE_CONSOLE_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_console_ep: u64 = 0;

/// Service readiness notification (`ROLE_READINESS_NTFN`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_readiness_ntfn: u64 = 0;

/// Initrd device untyped (`ROLE_INITRD_UNTYPED`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_initrd_untyped: u64 = 0;

/// Framebuffer device untyped (`ROLE_FB_UNTYPED`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_fb_untyped: u64 = 0;

/// PCI configuration space I/O port (`ROLE_PCI_IOPORT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_pci_ioport: u64 = 0;

/// COM1 serial I/O port (`ROLE_COM1_IOPORT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_com1_ioport: u64 = 0;

/// Process-local service endpoint (`ROLE_SERVICE_EP`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_service_ep: u64 = 0;

/// Win32 subsystem server IPC endpoint (`ROLE_WIN32SRV_CLIENT`).
/// Populated by the cap_table reader for processes that request a win32
/// client cap; PE binaries receive the same value via the kernel32.dll
/// role-map mirror.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_win32srv_ep: u64 = 0;

/// Saved auxv pointer for runtime metadata lookups.
/// Set by the active startup path (for example, basalt CRT) before main().
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_saved_auxv: *const u64 = ::core::ptr::null();

/// ELF TLS template address (runtime address of `.tdata` in the loaded binary).
/// Set by rtld after processing PT_TLS.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_tls_template: u64 = 0;

/// Size of `.tdata` section (initialized TLS data to copy).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_tls_filesz: u64 = 0;

/// Total static TLS size across the executable and all loaded PT_TLS DSOs.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_tls_memsz: u64 = 0;

/// Maximum alignment required by the process static TLS layout.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_tls_align: u64 = 1;

/// Number of populated entries in `__trona_tls_modules`.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_tls_module_count: u64 = 0;

/// Per-module static TLS metadata exported by rtld.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_tls_modules: [StaticTlsModule; MAX_STATIC_TLS_MODULES] =
    [StaticTlsModule::zeroed(); MAX_STATIC_TLS_MODULES];

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
    tls::current_ipc_ctx()
}

unsafe fn runtime_resolve_cspace_layout_from_auxv(
    auxv: *const u64,
) -> Option<*const TronaCspaceLayoutV1> {
    unsafe {
        let mut p = auxv;
        while !p.is_null() {
            let tag = *p;
            let val = *p.add(1);
            if tag == 0 {
                break;
            }
            if tag == AT_TRONA_CSPACE_LAYOUT && val != 0 {
                let layout = val as *const TronaCspaceLayoutV1;
                if !layout.is_null() && (*layout).version == TronaCspaceLayoutV1::VERSION {
                    return Some(layout);
                }
                return None;
            }
            p = p.add(2);
        }
        None
    }
}

unsafe fn runtime_resolve_slot_pool_from_auxv(auxv: *const u64) -> (u64, u64, u64) {
    unsafe {
        let mut slot_base = 0u64;
        let mut slot_count = 0u64;
        let mut cspace_ntfn = 0u64;

        if let Some(layout) = runtime_resolve_cspace_layout_from_auxv(auxv) {
            slot_base = (*layout).alloc_base;
            slot_count = (*layout).alloc_count();
        }

        let mut p = auxv;
        while !p.is_null() {
            let tag = *p;
            let val = *p.add(1);
            if tag == 0 {
                break;
            }
            if tag == AT_TRONA_CSPACE_NTFN {
                cspace_ntfn = val;
            }
            p = p.add(2);
        }

        (slot_base, slot_count, cspace_ntfn)
    }
}

pub unsafe fn runtime_set_auxv(auxv: *const u64) {
    unsafe {
        __trona_saved_auxv = auxv;
        // Install role-based cap slots into the `__trona_cap_*` weak
        // symbols. For dynamic binaries this is redundant with the rtld
        // export path (rtld writes the same symbols via
        // `resolve_symbol_addr_in_object` before transferring control),
        // but for static-linked binaries (basalt CRT path) this is the
        // only place the slots get populated. If the spawner did not
        // emit `AT_TRONA_CAP_TABLE`, `runtime_install_from_auxv` is a
        // no-op and the legacy `AT_TRONA_*_EP` tags remain the source
        // of truth (used by kernel→init bootstrap until Stage 5).
        let _ = cap_table::runtime_install_from_auxv(auxv);
    }
}

pub fn runtime_get_cspace_layout() -> Option<TronaCspaceLayoutV1> {
    unsafe {
        let auxv = __trona_saved_auxv;
        if auxv.is_null() {
            return None;
        }
        let layout = runtime_resolve_cspace_layout_from_auxv(auxv)?;
        Some(*layout)
    }
}

pub fn runtime_get_slot_pool() -> Option<(u64, u64, u64)> {
    unsafe {
        let auxv = __trona_saved_auxv;
        let (slot_base, slot_count, mut cspace_ntfn) =
            if !auxv.is_null() { runtime_resolve_slot_pool_from_auxv(auxv) } else { (0, 0, 0) };
        if __trona_cspace_ntfn != 0 {
            cspace_ntfn = __trona_cspace_ntfn;
        }

        if slot_base != 0 && slot_count != 0 {
            Some((slot_base, slot_count, cspace_ntfn))
        } else {
            None
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trona_runtime_set_auxv(auxv: *const u64) {
    unsafe { runtime_set_auxv(auxv) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trona_runtime_get_slot_pool(
    base_out: *mut u64,
    count_out: *mut u64,
    cspace_ntfn_out: *mut u64,
) -> i32 {
    unsafe {
        if base_out.is_null() || count_out.is_null() || cspace_ntfn_out.is_null() {
            return -1;
        }
        let Some((base, count, cspace_ntfn)) = runtime_get_slot_pool() else {
            return -1;
        };
        *base_out = base;
        *count_out = count;
        *cspace_ntfn_out = cspace_ntfn;
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
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.line.str(s.as_bytes());
        Ok(())
    }
}

fn panic_getpid() -> Option<u64> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = protocol::PM_GETPID;
        msg.length = 0;

        let err = ipc::call_ctx(
            current_ipc_ctx(),
            caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        Some(reply.regs[0])
    }
}

#[panic_handler]
fn panic(info: &::core::panic::PanicInfo) -> ! {
    let mut line = serial::LineBuf::new();
    line.str(b"[PANIC] userspace");

    if let Some(pid) = panic_getpid() {
        line.str(b" pid=");
        line.dec(pid);
    }

    if let Some(location) = info.location() {
        line.str(b" at ");
        line.str(location.file().as_bytes());
        line.putc(b':');
        line.dec(location.line() as u64);
        line.putc(b':');
        line.dec(location.column() as u64);
    }

    {
        let mut writer = SerialFmtWriter { line: &mut line };
        let _ = write!(&mut writer, ": {}", info.message());
    }

    line.putc(b'\n');
    line.flush();
    loop {
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

// ---------------------------------------------------------------------------
// C ABI exports: IPC operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_invoke(
    cap: Cap,
    label: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> TronaResult {
    invoke::invoke(cap, label, arg0, arg1, arg2, arg3)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_send(ep: Cap, msg: *const TronaMsg) -> i32 {
    unsafe { ipc::send_ctx(current_ipc_ctx(), ep, msg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_recv(ep: Cap, msg: *mut TronaMsg, badge: *mut u64) -> i32 {
    unsafe { ipc::recv_ctx(current_ipc_ctx(), ep, msg, badge) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_call(ep: Cap, msg: *const TronaMsg, reply: *mut TronaMsg) -> i32 {
    unsafe { ipc::call_ctx(current_ipc_ctx(), ep, msg, reply) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_reply_recv(
    ep: Cap,
    reply: *const TronaMsg,
    out_msg: *mut TronaMsg,
    badge: *mut u64,
) -> i32 {
    unsafe { ipc::reply_recv_ctx(current_ipc_ctx(), ep, reply, out_msg, badge) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_nbsend(ep: Cap, msg: *const TronaMsg) -> i32 {
    unsafe { ipc::nbsend_ctx(current_ipc_ctx(), ep, msg) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Notification operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_signal(ntfn: Cap, bits: u64) -> i32 {
    syscall::syscall(SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0).error as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_wait(ntfn: Cap) -> u64 {
    syscall::syscall(SYS_WAIT, ntfn, 0, 0, 0, 0, 0).value
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_poll(ntfn: Cap, bits: *mut u64) -> i32 {
    let r = syscall::syscall(SYS_POLL, ntfn, 0, 0, 0, 0, 0);
    if r.error == 0 && !bits.is_null() {
        unsafe {
            *bits = r.value;
        }
    }
    r.error as i32
}

// ---------------------------------------------------------------------------
// C ABI exports: Misc syscalls
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_yield() {
    syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_debug_putchar(c: u8) {
    syscall::syscall(SYS_DEBUG_PUTCHAR, c as u64, 0, 0, 0, 0, 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_debug_dump_state() {
    syscall::syscall(SYS_DEBUG_DUMP_STATE, 0, 0, 0, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// C ABI exports: Capability invocations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_untyped_retype(
    untyped: Cap,
    new_type: u64,
    size_bits: u64,
    dest_slot: u64,
) -> i32 {
    invoke::untyped_retype(untyped, new_type, size_bits, dest_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_configure(tcb: Cap, rip: u64, rsp: u64, ipc_buf: u64) -> i32 {
    invoke::tcb_configure(tcb, rip, rsp, ipc_buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_resume(tcb: Cap) -> i32 {
    invoke::tcb_resume(tcb)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_space(tcb: Cap, cspace: Cap, vspace: Cap) -> i32 {
    invoke::tcb_set_space(tcb, cspace, vspace)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_fault_handler(tcb: Cap, fault_ep: Cap) -> i32 {
    invoke::tcb_set_fault_handler(tcb, fault_ep)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_ipc_buffer(tcb: Cap, addr: u64) -> i32 {
    invoke::tcb_set_ipc_buffer(tcb, addr)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_write_registers(tcb: Cap, flags: u64, rip: u64, rsp: u64) -> i32 {
    invoke::tcb_write_registers(tcb, flags, rip, rsp)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_suspend(tcb: Cap) -> i32 {
    invoke::tcb_suspend(tcb)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_sc_configure(sc: Cap, budget_us: u64, period_us: u64) -> i32 {
    invoke::sc_configure(sc, budget_us, period_us)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_sc_bind(sc: Cap, tcb: Cap) -> i32 {
    invoke::sc_bind(sc, tcb)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_map(vspace: Cap, frame: Cap, vaddr: u64, flags: u64) -> i32 {
    invoke::vspace_map(vspace, frame, vaddr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_unmap(vspace: Cap, vaddr: u64) -> i32 {
    invoke::vspace_unmap(vspace, vaddr)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_map_pt(vspace: Cap, frame: Cap, vaddr: u64, level: u64) -> i32 {
    invoke::vspace_map_pt(vspace, frame, vaddr, level)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_walk(vspace: Cap, start_vaddr: u64, max_entries: u64) -> i32 {
    invoke::vspace_walk(vspace, start_vaddr, max_entries)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_copy_page(src_vspace: Cap, src_vaddr: u64, dst_frame: Cap) -> i32 {
    invoke::vspace_copy_page(src_vspace, src_vaddr, dst_frame)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_clone_cow_page(
    src_vspace: Cap,
    src_vaddr: u64,
    dst_vspace: Cap,
    dst_vaddr: u64,
) -> i32 {
    invoke::vspace_clone_cow_page(src_vspace, src_vaddr, dst_vspace, dst_vaddr)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_copy(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    rights: u64,
) -> i32 {
    invoke::cnode_copy(src_cnode, src_slot, dest_cnode, dest_slot, rights)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_mint(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    badge: u64,
) -> i32 {
    invoke::cnode_mint(src_cnode, src_slot, dest_cnode, dest_slot, badge)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_move(
    dest_cnode: Cap,
    dest_slot: u64,
    src_cnode: Cap,
    src_slot: u64,
) -> i32 {
    invoke::cnode_move(dest_cnode, dest_slot, src_cnode, src_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_mutate(
    dest_cnode: Cap,
    dest_slot: u64,
    src_cnode: Cap,
    src_slot: u64,
    badge: u64,
) -> i32 {
    invoke::cnode_mutate(dest_cnode, dest_slot, src_cnode, src_slot, badge)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_save_caller(cnode: Cap, slot: u64) -> i32 {
    invoke::cnode_save_caller(cnode, slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_delete(cnode: Cap, slot: u64) -> i32 {
    invoke::cnode_delete(cnode, slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_revoke(cnode: Cap, slot: u64) -> i32 {
    invoke::cnode_revoke(cnode, slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_irq_handler_ack(irq_handler: Cap) -> i32 {
    invoke::irq_handler_ack(irq_handler)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_irq_handler_set_notification(irq_handler: Cap, ntfn: Cap) -> i32 {
    invoke::irq_handler_set_notification(irq_handler, ntfn)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_tls_base(tcb: Cap, tls_base: u64) -> i32 {
    invoke::tcb_set_tls_base(tcb, tls_base)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_futex_wait(addr: *const u32, expected: u32) -> i32 {
    syscall::syscall(SYS_FUTEX, addr as u64, FUTEX_WAIT, expected as u64, 0, 0, 0).error as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_futex_wake(addr: *const u32, count: u32) -> i32 {
    syscall::syscall(SYS_FUTEX, addr as u64, FUTEX_WAKE, count as u64, 0, 0, 0).value as i32
}

// ---------------------------------------------------------------------------
// C ABI exports: Serial helpers
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_serial_puts(s: *const u8) {
    if s.is_null() {
        return;
    }
    unsafe {
        let mut i = 0;
        while *s.add(i) != 0 {
            serial::serial_putc(*s.add(i));
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_serial_hex(val: u64) {
    serial::serial_hex(val);
}
