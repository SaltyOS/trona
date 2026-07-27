// SPDX-License-Identifier: GPL-2.0-only
//
//! C-ABI exports — `trona_*` symbols rtld resolves from
//! `libtrona.so`. Currently four logical groups:
//!
//! * IPC primitives (`trona_send / _recv / _call / _mp_write_reply_read`).
//! * Capability invoke wrappers (`trona_invoke / _untyped_retype /
//!   _tcb_* / _sc_* / _vspace_* / _cnode_* / _irq_* / _futex_*`).
//! * Lifecycle / yield (`trona_yield`).
//! * Debug surfaces (`trona_debug_putchar / _debug_dump_state /
//!   _serial_*`).
//!
//! Process-level lifecycle (`trona_runtime_install` etc.) lives in
//! [`crate`] root. Per-process Rust client APIs (vfs / mm) are not
//! exposed as `trona_*` C symbols — callers use the Rust modules
//! `trona_runtime::client::vfs` / `client::mm` directly.
//!
//! Every symbol is `#[unsafe(no_mangle)] pub extern "C"` so the
//! dynamic linker can resolve them by name.

use crate::client::caps;
use crate::current_ipc_ctx;
use crate::debug::serial;
use trona_kernel::core_types::{Cap, TronaMsg, TronaResult};
use trona_kernel::{invoke, ipc, syscall};

#[unsafe(no_mangle)]
pub extern "C" fn trona_invoke(
    cap: Cap,
    label: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> TronaResult {
    syscall::invoke(cap, label, arg0, arg1, arg2, arg3)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_send(ep: Cap, msg: *const TronaMsg) -> i32 {
    unsafe { ipc::mp_write_ctx(current_ipc_ctx(), ep, msg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_recv(ep: Cap, msg: *mut TronaMsg, badge: *mut u64) -> i32 {
    unsafe { ipc::mp_read_ctx(current_ipc_ctx(), ep, msg, badge) }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_call(ep: Cap, msg: *const TronaMsg, reply: *mut TronaMsg) -> i32 {
    unsafe {
        ipc::mp_call_ctx(
            current_ipc_ctx(),
            ep,
            msg,
            reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_mp_write_reply_read(
    ep: Cap,
    reply: *const TronaMsg,
    out_msg: *mut TronaMsg,
    badge: *mut u64,
) -> i32 {
    unsafe { ipc::mp_write_reply_read_ctx(current_ipc_ctx(), ep, reply, out_msg, badge) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Misc syscalls
//
// Notification operations (`trona_signal` / `trona_wait` / `trona_poll`)
// are retired — endpoints / notifications no longer exist in the new
// kernite ABI. Subsystems that need a wakeable signal use a Watch on an
// EventQueue against a state-bit on a kernel object (Timer, IRQ, MP).
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn trona_yield() {
    syscall::yield_now();
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_debug_putchar(c: u8) {
    syscall::invoke(
        caps::kernel_debug_cap().addr(),
        uapi::KERNITE_INV_KDEBUG_PUTCHAR as u64,
        c as u64,
        0,
        0,
        0,
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_debug_dump_state() {
    syscall::invoke(
        caps::kernel_debug_cap().addr(),
        uapi::KERNITE_INV_KDEBUG_DUMP_STATE as u64,
        0,
        0,
        0,
        0,
    );
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
    invoke::untyped_retype(untyped.into(), new_type, size_bits, dest_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_configure(tcb: Cap, rip: u64, rsp: u64, ipc_buf: u64) -> i32 {
    invoke::tcb_configure(tcb.into(), rip, rsp, ipc_buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_start(tcb: Cap) -> i32 {
    invoke::tcb_start(tcb.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_stop(tcb: Cap) -> i32 {
    invoke::tcb_stop(tcb.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_kill(tcb: Cap) -> i32 {
    invoke::tcb_kill(tcb.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_space(tcb: Cap, cspace: Cap, vspace: Cap) -> i32 {
    invoke::tcb_set_space(tcb.into(), cspace.into(), vspace.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_fault_pipe(tcb: Cap, fault_mp: Cap) -> i32 {
    invoke::tcb_set_fault_pipe(tcb.into(), fault_mp.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_ipc_buffer(tcb: Cap, addr: u64) -> i32 {
    invoke::tcb_set_ipc_buffer(tcb.into(), addr)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_write_registers(tcb: Cap, flags: u64, rip: u64, rsp: u64) -> i32 {
    invoke::tcb_write_registers(tcb.into(), flags, rip, rsp)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_priority(tcb: Cap, priority: u64) -> i32 {
    invoke::tcb_set_priority(tcb.into(), priority)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_sched_class(tcb: Cap, sched_class: u64) -> i32 {
    invoke::tcb_set_sched_class(tcb.into(), sched_class)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_sc_configure(sc: Cap, budget_ns: u64, period_ns: u64) -> i32 {
    invoke::sc_configure(sc.into(), budget_ns, period_ns)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_sc_bind(sc: Cap, tcb: Cap) -> i32 {
    invoke::sc_bind(sc.into(), tcb.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_map(vspace: Cap, frame: Cap, vaddr: u64, flags: u64) -> i32 {
    invoke::vspace_map(vspace.into(), frame.into(), vaddr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_unmap(vspace: Cap, vaddr: u64) -> i32 {
    invoke::vspace_unmap(vspace.into(), vaddr)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_map_pt(vspace: Cap, page_table: Cap, vaddr: u64, level: u64) -> i32 {
    invoke::vspace_map_pt(vspace.into(), page_table.into(), vaddr, level)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_walk(vspace: Cap, start_vaddr: u64, max_entries: u64) -> i32 {
    invoke::vspace_walk(vspace.into(), start_vaddr, max_entries)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_vspace_copy_page(src_vspace: Cap, src_vaddr: u64, dst_frame: Cap) -> i32 {
    invoke::vspace_copy_page(src_vspace.into(), src_vaddr, dst_frame.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_copy(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    rights: u64,
) -> i32 {
    invoke::cnode_copy(
        src_cnode.into(),
        src_slot,
        dest_cnode.into(),
        dest_slot,
        rights,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_mint(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    badge: u64,
) -> i32 {
    invoke::cnode_mint(
        src_cnode.into(),
        src_slot,
        dest_cnode.into(),
        dest_slot,
        badge,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_move(
    dest_cnode: Cap,
    dest_slot: u64,
    src_cnode: Cap,
    src_slot: u64,
) -> i32 {
    invoke::cnode_move(dest_cnode.into(), dest_slot, src_cnode.into(), src_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_mutate(
    dest_cnode: Cap,
    dest_slot: u64,
    src_cnode: Cap,
    src_slot: u64,
    badge: u64,
) -> i32 {
    invoke::cnode_mutate(
        dest_cnode.into(),
        dest_slot,
        src_cnode.into(),
        src_slot,
        badge,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_delete(cnode: Cap, slot: u64) -> i32 {
    invoke::cnode_delete(cnode.into(), slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_cnode_revoke(cnode: Cap, slot: u64) -> i32 {
    invoke::cnode_revoke(cnode.into(), slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_irq_ack(irq_handler: Cap) -> i32 {
    invoke::irq_ack(irq_handler.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_irq_bind_eq(irq_handler: Cap, eq: Cap) -> i32 {
    invoke::irq_bind_eq(irq_handler.into(), eq.into(), 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_irq_unbind_eq(irq_handler: Cap) -> i32 {
    invoke::irq_unbind_eq(irq_handler.into())
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_tcb_set_tls_base(tcb: Cap, tls_base: u64) -> i32 {
    invoke::tcb_set_tls_base(tcb.into(), tls_base)
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_futex_wait(addr: *const u32, expected: u32) -> i32 {
    syscall::futex_wait(addr, expected) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn trona_futex_wake(addr: *const u32, count: u32) -> i32 {
    syscall::futex_wake(addr, count) as i32
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
