//! Safe getters for well-known capability slots passed via the startup block.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Each well-known capability lives in the child cspace at a slot chosen by
//! the spawner. rtld walks the auxv vector at process startup and writes the
//! slot number into the matching `__trona_cap_*` weak symbol on `lib.rs`.
//! Lib code calls the corresponding getter here instead of hard-coding the
//! slot number, so the same code runs against any spawner layout.
//!
//! Every cap getter returns a [`LeakedCapRef`]: a process-lifetime role cap
//! delivered through the startup cap table (or resolved lazily via the name
//! service) that no scope ever releases. A missing capability surfaces as
//! [`LeakedCapRef::NULL`]; callers test [`LeakedCapRef::is_null`] and either
//! fall back or fail loudly. `next_free_slot` is the lone exception — it
//! returns the raw slot-reservation cursor, not a capability.

use trona_kernel::core_types::{Cap, LeakedCapRef};

#[inline]
fn read(p: *const u64) -> u64 {
    // SAFETY: each `__trona_cap_*` weak symbol is initialized exactly once
    // by rtld (or the static CRT) before user code runs. After that point
    // the slot is read-only for the lifetime of the process, so a volatile
    // load through a raw pointer is sound and avoids the Rust 2024 ban on
    // taking references to `static mut`.
    unsafe { ::core::ptr::read_volatile(p) }
}

/// Process manager IPC endpoint.
#[inline]
pub fn init_ep() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_init_ep))
}

/// VFS server IPC endpoint. Resolved lazily on first call via
/// `NAMESRV_LOOKUP("vfs")` against the namespace root.
#[inline]
pub fn vfs_ep() -> LeakedCapRef {
    let cached = read(&raw const crate::__trona_cap_vfs_ep);
    if cached != 0 {
        return LeakedCapRef::flat(cached);
    }
    LeakedCapRef::flat(crate::client::lazy_resolve::resolve_into(
        b"vfs",
        &raw mut crate::__trona_cap_vfs_ep,
    ))
}

/// Code-loading authority (`ldsrv`) IPC endpoint. Resolved lazily on first
/// call via `NAMESRV_LOOKUP("ldsrv")` against the namespace root. The dynamic
/// linker resolves `DT_NEEDED` libraries and (caller-VFS-checked) main images
/// through it.
#[inline]
pub fn ldsrv_ep() -> LeakedCapRef {
    let cached = read(&raw const crate::__trona_cap_ldsrv_ep);
    if cached != 0 {
        return LeakedCapRef::flat(cached);
    }
    LeakedCapRef::flat(crate::client::lazy_resolve::resolve_into(
        b"ldsrv",
        &raw mut crate::__trona_cap_ldsrv_ep,
    ))
}

/// Name service IPC endpoint.
#[inline]
pub fn namesrv_ep() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_namesrv_ep))
}

/// Per-process POSIX signal `MessagePipe` consumer cap. The spawner
/// holds the producer side and writes signal records here; the POSIX
/// layer (`trona_posix::wakeup`) drains via `MP_READ` driven by a
/// Watch on `KERNITE_STATE_READABLE`.
#[inline]
pub fn signal_pipe() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_signal_pipe))
}

/// Resource server IPC endpoint. Resolved lazily on first call via
/// `NAMESRV_LOOKUP("rsrcsrv")` against the namespace root.
#[inline]
pub fn rsrcsrv_ep() -> LeakedCapRef {
    let cached = read(&raw const crate::__trona_cap_rsrcsrv_ep);
    if cached != 0 {
        return LeakedCapRef::flat(cached);
    }
    LeakedCapRef::flat(crate::client::lazy_resolve::resolve_into(
        b"rsrcsrv",
        &raw mut crate::__trona_cap_rsrcsrv_ep,
    ))
}

/// Console server IPC endpoint. Resolved lazily on first call via
/// `NAMESRV_LOOKUP("console")` against the namespace root.
#[inline]
pub fn console_ep() -> LeakedCapRef {
    let cached = read(&raw const crate::__trona_cap_console_ep);
    if cached != 0 {
        return LeakedCapRef::flat(cached);
    }
    LeakedCapRef::flat(crate::client::lazy_resolve::resolve_into(
        b"console",
        &raw mut crate::__trona_cap_console_ep,
    ))
}

/// Userland log service IPC endpoint. Delivered by init through the
/// startup cap table once `logsrv` is ready.
#[inline]
pub fn log_ep() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_log_ep))
}

/// Network-stack server IPC endpoint. Resolved lazily on first
/// call via `NAMESRV_LOOKUP("netsrv")`. Consumers (procfs's
/// `/proc/net/*` generators, the POSIX socket layer) reach the
/// netsrv ring buffer through this cap.
#[inline]
pub fn netsrv_ep() -> LeakedCapRef {
    let cached = read(&raw const crate::__trona_cap_netsrv_ep);
    if cached != 0 {
        return LeakedCapRef::flat(cached);
    }
    LeakedCapRef::flat(crate::client::lazy_resolve::resolve_into(
        b"netsrv",
        &raw mut crate::__trona_cap_netsrv_ep,
    ))
}

/// Initrd device untyped.
#[inline]
pub fn initrd_untyped() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_initrd_untyped))
}

/// Framebuffer device untyped.
#[inline]
pub fn fb_untyped() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_fb_untyped))
}

/// PCI configuration space I/O port.
#[inline]
pub fn pci_ioport() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_pci_ioport))
}

/// COM1 serial I/O port.
#[inline]
pub fn com1_ioport() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_com1_ioport))
}

/// COM1 serial IRQ handler.
#[inline]
pub fn com1_irq() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_com1_irq))
}

/// COM1 serial IRQ delivery notification.
#[inline]
pub fn com1_ntfn() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_com1_ntfn))
}

/// PS/2 keyboard I/O port.
#[inline]
pub fn kbd_ioport() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_kbd_ioport))
}

/// PS/2 keyboard IRQ handler.
#[inline]
pub fn kbd_irq() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_kbd_irq))
}

/// Root device-control cap for dynamic device creation.
#[inline]
pub fn device_control() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_device_control))
}

/// Process-local service receive endpoint.
#[inline]
pub fn service_recv_ep() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_service_ep))
}

/// Client-facing peer of the process-local service endpoint.
#[inline]
pub fn service_client_ep() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_service_client_ep))
}

/// Duplicate the client-facing service endpoint into a fresh transfer slot.
///
/// MessagePipe cap transfer *moves* the sender's CNode entry into the
/// receiver. Services publishing to namesrv must keep their own
/// `ROLE_SERVICE_CLIENT_EP` for later self-wake messages and
/// re-publication, so they send a duplicate. The returned
/// [`TransferCap`] owns the duplicate slot: stage `tc.slot()` into the
/// send window, issue the call, and let the guard drop — its `Drop`
/// reclaims the slot whether the kernel moved the cap out (success) or
/// left it in place (send failed). Returns `None` when this process
/// carries no service-client endpoint.
///
/// [`TransferCap`]: crate::core::slot_alloc::TransferCap
pub fn service_client_ep_for_transfer() -> Option<crate::core::slot_alloc::TransferCap> {
    let src = service_client_ep();
    if src.is_null() {
        return None;
    }
    crate::core::slot_alloc::dup_for_transfer(src.cap_ref())
}

/// `KernelRng` cap (delivered via `ROLE_KERNEL_RNG`).
#[inline]
pub fn kernel_rng_cap() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_kernel_rng))
}

/// `Clock` cap (delivered via `ROLE_CLOCK`). Use with
/// `KERNITE_INV_CLOCK_READ` and `KERNITE_CLOCK_ID_*` arg.
#[inline]
pub fn clock_cap() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_clock))
}

/// `SystemControl` cap (delivered via `ROLE_SYSTEM_CONTROL`).
/// Held by the supervisor; carries `SHUTDOWN` / `REBOOT` rights.
#[inline]
pub fn system_control_cap() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_system_control))
}

/// `SystemInfo` cap (delivered via `ROLE_SYSTEM_INFO`).
#[inline]
pub fn system_info_cap() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_system_info))
}

/// `KernelDebug` cap (delivered via `ROLE_KERNEL_DEBUG`). Privileged —
/// only debug-authorised processes carry it.
#[inline]
pub fn kernel_debug_cap() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_cap_kernel_debug))
}

/// Win32 subsystem server IPC endpoint. Resolved lazily on first call
/// via `NAMESRV_LOOKUP("win32_csrss")` against the namespace root —
/// the publish name win32_csrss uses for its REGISTER must match.
#[inline]
pub fn win32srv_ep() -> LeakedCapRef {
    let cached = read(&raw const crate::__trona_cap_win32srv_ep);
    if cached != 0 {
        return LeakedCapRef::flat(cached);
    }
    LeakedCapRef::flat(crate::client::lazy_resolve::resolve_into(
        b"win32_csrss",
        &raw mut crate::__trona_cap_win32srv_ep,
    ))
}

/// Memory manager server IPC endpoint. Modern spawners deliver the
/// per-client self-tier send through `ROLE_MMSRV_CLIENT` because rtld
/// may need it before lazy resolution is safe. The namesrv
/// `MM_BIND_CLIENT_SELF` path remains as a compatibility fallback for
/// older startup records.
#[inline]
pub fn mmsrv_ep() -> LeakedCapRef {
    let cached = read(&raw const crate::__trona_cap_mmsrv_ep);
    if cached != 0 {
        return LeakedCapRef::flat(cached);
    }
    LeakedCapRef::flat(crate::client::lazy_resolve::resolve_into(
        b"mmsrv",
        &raw mut crate::__trona_cap_mmsrv_ep,
    ))
}

/// Main thread SchedContext cap (delivered via `ROLE_SC_CAP` in the startup cap table).
#[inline]
pub fn sc_cap() -> LeakedCapRef {
    LeakedCapRef::flat(read(&raw const crate::__trona_sc_cap))
}

/// Next free persistent CNode slot after RTLD startup allocations.
///
/// This is a raw slot-reservation cursor, **not** a capability. The
/// cursor covers frame caps, the rtld's embedded slot-allocator window,
/// and any other RTLD-owned startup capabilities kept alive for the
/// process, so it is returned as a bare [`Cap`] slot index.
#[inline]
pub fn next_free_slot() -> Cap {
    read(&raw const crate::__trona_next_free_slot)
}

/// Resolve a service-local role id to the child-cspace slot the spawner
/// placed the cap at. Returns [`LeakedCapRef::NULL`] when the role is
/// absent from this process's cap_table.
///
/// Call through the convenience wrapper `local_by_name` whenever the key
/// is a literal `"<consumer>:<peer>"` pair; it keeps the djb2 hash close
/// to the provider attachment declaration that produced the entry.
#[inline]
pub fn local_by_role_id(role_id: u32) -> LeakedCapRef {
    // SAFETY: `__trona_saved_auxv` is initialized once by rtld / CRT
    // before user code runs (see `runtime_set_auxv`). A raw-pointer
    // read avoids the Rust 2024 ban on references to `static mut`.
    let auxv = unsafe { ::core::ptr::read_volatile(&raw const crate::__trona_saved_auxv) };
    // SAFETY: `find_in_auxv` tolerates a null pointer and walks a
    // NUL-terminated auxv vector — contract documented on the callee.
    let tbl = unsafe { crate::spawn::cap_table::find_in_auxv(auxv) };
    match crate::spawn::cap_table::lookup(tbl, role_id) {
        Some(entry) => {
            if entry.flags & crate::spawn::role_consts::CAP_TBL_FLAG_RESERVED != 0 {
                LeakedCapRef::NULL
            } else {
                LeakedCapRef::flat(entry.slot as Cap)
            }
        }
        None => LeakedCapRef::NULL,
    }
}

/// Resolve a `"<consumer>:<peer>"` LOCAL_ROLE key to the child-cspace
/// slot. Hashes the key through the shared `djb2 → LOCAL_ROLE_BASE +
/// hash % LOCAL_ROLE_MOD` formula used by init's parser.
#[inline]
pub fn local_by_name(key: &[u8]) -> LeakedCapRef {
    local_by_role_id(crate::spawn::role_consts::local_role_id(key))
}

/// Declare a service-local cap getter that resolves a
/// `"<consumer>:<peer>"` key at compile time.
///
/// Usage:
///
/// ```ignore
/// trona::local_cap!(pcidrv_ep = "blkdrv:pcidrv_ep");
/// // ...
/// let ep = pcidrv_ep();
/// ```
///
/// The djb2 hash runs in `const` context so each call site is a single
/// table lookup. Returns [`LeakedCapRef::NULL`] when the spawner did not
/// attach the capability (same contract as [`local_by_name`]).
///
/// Prefer this macro over ad-hoc `local_by_name(b"...")` calls when the
/// key is a literal — it keeps the attachment name next to the getter
/// and avoids re-hashing on every call.
#[macro_export]
macro_rules! local_cap {
    ($vis:vis $name:ident = $key:literal) => {
        #[inline]
        $vis fn $name() -> ::trona_kernel::core_types::LeakedCapRef {
            const ROLE_ID: u32 =
                $crate::spawn::role_consts::local_role_id($key.as_bytes());
            $crate::client::caps::local_by_role_id(ROLE_ID)
        }
    };
    ($name:ident = $key:literal) => {
        $crate::local_cap!(pub(self) $name = $key);
    };
}
