// SPDX-License-Identifier: GPL-2.0-only
//
//! Weak / strong symbols rtld and the CRT fill in during process
//! startup. Every cap slot, IPC context, runtime descriptor, and
//! TLS image referenced by trona_runtime's exports lives here.

use trona_kernel::core_types::{
    IpcContext, MAX_STATIC_TLS_MODULES, StaticTlsModule, TronaRuntimeV1,
};

/// Initialized by `rtld` (dynamic) or the CRT (static) before `main`.
#[unsafe(no_mangle)]
pub static mut __trona_ipc_ctx: IpcContext = IpcContext::new();

/// Next available persistent CNode slot. Weak symbol overridden by `rtld`
/// with the first post-startup free slot after the rtld has reserved its own
/// frame, library-MO, and embedded slot-allocator capabilities.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_next_free_slot: u64 = 64;

/// SchedContext capability slot for the main thread
/// (from the startup cap-table `ROLE_SC_CAP` entry). 0 if not provided.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_sc_cap: u64 = 0;

// ---------------------------------------------------------------------------
// Well-known capability slots passed by the spawner via the startup block's
// embedded cap_table.
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

/// Init supervisor control endpoint (`ROLE_INIT_CONTROL`). Carries every
/// process-lifecycle and POSIX-personality RPC (spawn, exit, fork, exec,
/// wait, kill, credentials, limits, sigaction, threads, introspection).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_init_ep: u64 = 0;

/// VFS server IPC endpoint (`ROLE_VFS_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_vfs_ep: u64 = 0;

/// Name service IPC endpoint (`ROLE_NAMESRV_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_namesrv_ep: u64 = 0;

/// Per-process POSIX signal MessagePipe consumer side (`ROLE_SIGNAL_PIPE`).
/// Spawner (init) holds the producer side and writes signal records
/// (`regs[0] = signum`, `regs[1] = info`) here. Consumer drains via
/// `MP_READ` driven by the substrate POSIX layer's `wakeup_eq` Watch.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_signal_pipe: u64 = 0;

/// Resource server IPC endpoint (`ROLE_RSRCSRV_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_rsrcsrv_ep: u64 = 0;

/// Console server IPC endpoint (`ROLE_CONSOLE_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_console_ep: u64 = 0;

/// Userland log service IPC endpoint (`ROLE_LOG_CLIENT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_log_ep: u64 = 0;

/// Code-loading authority IPC endpoint (`ROLE_LDSRV_CLIENT`). Resolved lazily
/// on first use via `NAMESRV_LOOKUP("ldsrv")`; the `caps::ldsrv_ep` getter
/// caches the result here. The dynamic linker resolves `DT_NEEDED` libraries
/// (and, after the caller's own VFS exec check, main images) through it.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_ldsrv_ep: u64 = 0;

/// Network-stack server IPC endpoint. There is no startup cap-table role for
/// this lazy-only service; `caps::netsrv_ep` resolves it on first use via
/// `NAMESRV_LOOKUP("netsrv")` and caches the result here for subsequent calls.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_netsrv_ep: u64 = 0;

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

/// COM1 serial IRQ handler (`ROLE_COM1_IRQ`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_com1_irq: u64 = 0;

/// COM1 serial IRQ delivery notification (`ROLE_COM1_NTFN`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_com1_ntfn: u64 = 0;

/// PS/2 keyboard I/O port (`ROLE_KBD_IOPORT`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_kbd_ioport: u64 = 0;

/// PS/2 keyboard IRQ handler (`ROLE_KBD_IRQ`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_kbd_irq: u64 = 0;

/// Root device-control cap for dynamic device creation (`ROLE_DEVICE_CONTROL`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_device_control: u64 = 0;

/// Process-local service receive endpoint (`ROLE_SERVICE_EP`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_service_ep: u64 = 0;

/// Client-facing peer of the process-local service endpoint
/// (`ROLE_SERVICE_CLIENT_EP`).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_service_client_ep: u64 = 0;

/// `KernelRng` cap (`ROLE_KERNEL_RNG`). Carries `KERNITE_INV_RNG_READ`.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_kernel_rng: u64 = 0;

/// `Clock` cap (`ROLE_CLOCK`). Carries `KERNITE_INV_CLOCK_READ` with
/// `KERNITE_CLOCK_ID_MONOTONIC` / `_REALTIME` arg.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_clock: u64 = 0;

/// `SystemControl` cap (`ROLE_SYSTEM_CONTROL`). Held only by the
/// supervisor; carries `KERNITE_INV_SYSTEM_SHUTDOWN`/`SYSTEM_REBOOT`.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_system_control: u64 = 0;

/// `SystemInfo` cap (`ROLE_SYSTEM_INFO`). Carries
/// `KERNITE_INV_SYSTEM_GET_INFO` / `_GET_MEMINFO`.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_system_info: u64 = 0;

/// `KernelDebug` cap (`ROLE_KERNEL_DEBUG`). Privileged debug-channel cap
/// carrying `KERNITE_INV_KDEBUG_*`. Only debug-authorised processes
/// receive it.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_cap_kernel_debug: u64 = 0;

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

/// Installed process runtime ABI published by rtld.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __trona_runtime: TronaRuntimeV1 = TronaRuntimeV1::zeroed();

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
