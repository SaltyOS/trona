//! Child process virtual address layout planner.
//!
//! Computes a `VmLayoutPlan` for a child process based on the actual sizes
//! of its ELF, RTLD, and shared library regions. Eliminates hardcoded VA
//! constants across init.
//!
//! Supports ASLR via `compute_vm_layout_randomized()`, which applies random
//! page-aligned offsets to the code base and stack base.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::core::server_consts::{CSPACE_EXPAND_BASE, MAX_CSPACE_EXPANSIONS};
use crate::spawn::stack_plan::StackLayoutSpec;
use trona_kernel::core_types::SaltyOSCspaceLayoutV1;

/// Top of user-space virtual address range (exclusive). 48-bit user VA on
/// every supported architecture; kernel owns the upper half.
pub const USER_VA_TOP: u64 = 1u64 << 47;
/// Number of CSpace slots reserved at the top of a Pager / BootstrapAuthority
/// CNode for incoming cap_transfers (page-fault VSpace caps, RES_ADOPT_UNTYPED,
/// etc.). Sized generously because these are the only userland services that
/// receive raw caps in bulk.
pub const AUTHORITY_RECV_SLOT_COUNT: u64 = 1024;
/// Minimum child slot reserved for RTLD startup persistent allocation.
/// The field/layout name is historical: RTLD still retypes private frames
/// from this range, but any startup capability it keeps live (for example
/// shared-library MOs) also consumes from the same alloc window. The actual
/// `frame_slot_start` used by a given spawn may be higher when service
/// extras push the floor upward; treat this as a guaranteed lower bound only.
pub const CHILD_RTLD_FRAME_SLOT_START: u64 = 64;
/// Legacy alias. New code should use `CHILD_RTLD_FRAME_SLOT_START`.
pub const CHILD_FRAME_SLOT_BASE: u64 = CHILD_RTLD_FRAME_SLOT_START;

/// Child CSpace range reserved for RTLD bootstrap untyped slots. `_START`
/// is inclusive, `_END` is exclusive. Spawners report the actual handed-off
/// count in `SaltyOSCspaceLayoutV1.rtld_untyped_count`; the rest of the
/// reserved window stays empty so service-local extras can start above it
/// without per-spawner slot drift.
pub const CHILD_RTLD_UNTYPED_SLOT_START: u64 = 17;
pub const CHILD_RTLD_UNTYPED_SLOT_END: u64 = 24;

// Per-spawner private `COFF_*` offsets (into the spawner's own CSpace
// during spawn) live in each spawner's local module — init
// use different conventions and different values, so unifying them is
// unsafe. `trona::layout` only exposes the types and constants that are
// genuinely shared across all spawners.

// ---- ChildSlotAlloc + ChildCapLayout ----

/// Which spawner is calling `ChildCapLayout::from_alloc`. Controls which
/// fields get populated from the cursor.
///
/// * `Init` — allocates only the mandatory fixed ABI caps. Optional service
///   attachments such as pty/rootfs notifications are placed in service-local
///   extra slots so the cap table describes the slots actually populated by
///   the spawner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CapLayoutProfile {
    Init,
}

/// Sequential allocator that hands out child CNode slots one at a time.
pub struct ChildSlotAlloc {
    next: u64,
    limit: u64,
}

impl ChildSlotAlloc {
    /// Create a new allocator that hands out slots in `[start, limit)`.
    pub fn new(start: u64, limit: u64) -> Self {
        Self { next: start, limit }
    }

    /// Allocate the next free slot, or return `None` if the cursor would
    /// cross `limit`.
    pub fn alloc(&mut self) -> Option<u64> {
        if self.next >= self.limit {
            return None;
        }
        let s = self.next;
        self.next += 1;
        Some(s)
    }

    /// Peek at the next slot the cursor will return without consuming it.
    pub fn next_free(&self) -> u64 {
        self.next
    }
}

/// Layout of well-known capabilities in a child's CSpace, as chosen by a
/// spawner for one specific spawn.
///
/// A field value of `0` means the corresponding capability was not minted
/// for this child — not every process gets every cap (for example, only
/// display-class processes receive an `fb_untyped`, only PE processes
/// receive a `win32srv_ep`, and Init-profile spawns populate a smaller
/// field subset than Procmgr-profile spawns).
///
/// Slots 0/1/2 are always kernel ABI (`CAP_SELF_TCB` / `VSPACE` / `CSPACE`);
/// everything else is spawner-private and may move freely across spawns.
#[derive(Clone, Copy)]
pub struct ChildCapLayout {
    pub self_tcb: u64,
    pub self_vspace: u64,
    pub self_cspace: u64,
    pub service_ep: u64,
    pub service_client_ep: u64,
    pub sc: u64,
    pub initrd_untyped: u64,
    pub init_ep: u64,
    pub rsrcsrv_ep: u64,
    pub vfs_ep: u64,
    pub namesrv_ep: u64,
    pub signal_pipe: u64,
    pub mmsrv_ep: u64,
    pub console_ep: u64,
    pub log_ep: u64,
    pub win32srv_ep: u64,
    pub fb_untyped: u64,
    pub frame_slot_start: u64,
    /// Cursor position right after the well-known fields above were
    /// allocated. The cap_table builder uses this as the starting slot
    /// for service-local provider / source-slot attachments, which live
    /// in `[extras_base, frame_slot_start)`.
    pub extras_base: u64,
}

impl ChildCapLayout {
    /// All-zero layout used to initialize proctab / spawn scratch state.
    /// The fields are meaningless until the spawn/fork path rewrites them,
    /// which happens before the process becomes observable.
    pub const fn zeroed() -> Self {
        Self {
            self_tcb: 0,
            self_vspace: 0,
            self_cspace: 0,
            service_ep: 0,
            service_client_ep: 0,
            sc: 0,
            initrd_untyped: 0,
            init_ep: 0,
            rsrcsrv_ep: 0,
            vfs_ep: 0,
            namesrv_ep: 0,
            signal_pipe: 0,
            mmsrv_ep: 0,
            console_ep: 0,
            log_ep: 0,
            win32srv_ep: 0,
            fb_untyped: 0,
            frame_slot_start: 0,
            extras_base: 0,
        }
    }

    /// Build a layout by drawing slot positions from `alloc` under the
    /// given `profile`.
    ///
    /// The first three allocations are always pinned to 0/1/2 (kernel ABI
    /// for `CAP_SELF_TCB`/`VSPACE`/`CSPACE`). The remaining field set
    /// depends on `profile`:
    ///
    /// * `Init` — allocates service_ep, service_client_ep, sc,
    ///   signal_pipe, initrd_untyped, init_ep, and rsrcsrv_ep, then
    ///   leaves a gap for the shared RTLD untyped mirror window before
    ///   service-local extras begin.
    /// Returns `None` if the cursor runs out of slots.
    pub fn from_alloc(profile: CapLayoutProfile, alloc: &mut ChildSlotAlloc) -> Option<Self> {
        let mut layout = Self::zeroed();
        layout.self_tcb = alloc.alloc()?;
        layout.self_vspace = alloc.alloc()?;
        layout.self_cspace = alloc.alloc()?;

        match profile {
            CapLayoutProfile::Init => {
                layout.service_ep = alloc.alloc()?;
                layout.service_client_ep = alloc.alloc()?;
                layout.sc = alloc.alloc()?;
                layout.signal_pipe = alloc.alloc()?;
                layout.initrd_untyped = alloc.alloc()?;
                layout.init_ep = alloc.alloc()?;
                layout.rsrcsrv_ep = alloc.alloc()?;
                layout.frame_slot_start = CHILD_RTLD_FRAME_SLOT_START;
                // Init reserves a stable RTLD bootstrap-untyped window, so
                // service-local extras must start on the far side of it.
                let next_free = alloc.next_free();
                layout.extras_base = if next_free < CHILD_RTLD_UNTYPED_SLOT_END {
                    CHILD_RTLD_UNTYPED_SLOT_END
                } else {
                    next_free
                };
            }
        }

        Some(layout)
    }

    /// Emit one cap_table entry per system role this layout carries. Zero-
    /// valued fields are silently skipped by `CapTableBuilder::push`, so
    /// services that do not receive a given cap (for example `fb_untyped`
    /// on non-display services, or the optional notification fields on Init-profile
    /// spawns) never produce an entry for it.
    ///
    /// Slots 0/1/2 (`self_tcb` / `self_vspace` / `self_cspace`) are kernel-
    /// ABI fixed and deliberately do not appear here — the child reaches
    /// those via hard-coded constants, not the cap table.
    pub fn populate_cap_table(
        &self,
        builder: &mut crate::spawn::cap_table::CapTableBuilder,
    ) -> Result<(), crate::spawn::cap_table::CapTableErr> {
        use crate::spawn::role_consts::{
            CAP_TBL_FLAG_BADGED, CAP_TBL_FLAG_DEVICE_UT, CAP_TBL_FLAG_NOTIFICATION,
            CAP_TBL_FLAG_UNTYPED, ROLE_CONSOLE_CLIENT, ROLE_FB_UNTYPED, ROLE_INIT_CONTROL,
            ROLE_INITRD_UNTYPED, ROLE_LOG_CLIENT, ROLE_MMSRV_CLIENT, ROLE_NAMESRV_CLIENT,
            ROLE_RSRCSRV_CLIENT, ROLE_SC_CAP, ROLE_SERVICE_CLIENT_EP, ROLE_SERVICE_EP,
            ROLE_SIGNAL_PIPE, ROLE_VFS_CLIENT, ROLE_WIN32SRV_CLIENT,
        };
        builder.push(ROLE_INIT_CONTROL, self.init_ep, 0, CAP_TBL_FLAG_BADGED)?;
        builder.push(ROLE_VFS_CLIENT, self.vfs_ep, 0, 0)?;
        builder.push(ROLE_NAMESRV_CLIENT, self.namesrv_ep, 0, 0)?;
        builder.push(
            ROLE_SIGNAL_PIPE,
            self.signal_pipe,
            0,
            CAP_TBL_FLAG_NOTIFICATION,
        )?;
        builder.push(ROLE_MMSRV_CLIENT, self.mmsrv_ep, 0, CAP_TBL_FLAG_BADGED)?;
        builder.push(ROLE_SC_CAP, self.sc, 0, 0)?;
        builder.push(ROLE_CONSOLE_CLIENT, self.console_ep, 0, 0)?;
        builder.push(ROLE_LOG_CLIENT, self.log_ep, 0, 0)?;
        builder.push(ROLE_SERVICE_EP, self.service_ep, 0, 0)?;
        builder.push(ROLE_SERVICE_CLIENT_EP, self.service_client_ep, 0, 0)?;
        builder.push(ROLE_WIN32SRV_CLIENT, self.win32srv_ep, 0, 0)?;
        builder.push(ROLE_RSRCSRV_CLIENT, self.rsrcsrv_ep, 0, CAP_TBL_FLAG_BADGED)?;
        builder.push(
            ROLE_INITRD_UNTYPED,
            self.initrd_untyped,
            0,
            CAP_TBL_FLAG_UNTYPED | CAP_TBL_FLAG_DEVICE_UT,
        )?;
        builder.push(
            ROLE_FB_UNTYPED,
            self.fb_untyped,
            0,
            CAP_TBL_FLAG_UNTYPED | CAP_TBL_FLAG_DEVICE_UT,
        )?;
        Ok(())
    }
}

// ---- Default VA addresses shared by spawners and layout computation ----
// Low-VA region holds IPC buffer, ELF code, RTLD, shared libs, and the
// scratch page. Stack is anchored near the top of the user VA space so
// it has room to grow under a large per-service reserve (see
// `StackLayoutSpec`) without colliding with code or mmap.
pub const IPC_BUF_BASE: u64 = 0x0000_0000_0020_0000;
pub const ELF_CODE_BASE: u64 = 0x0000_0000_0021_0000;
const INITRD_BASE: u64 = 0x0000_0000_0100_0000;
/// Gap between existing mapped regions and the start of mmap allocations.
const MMAP_BASE_GAP: u64 = 0x1000_0000; // 256 MiB

/// Fixed user-VA anchor for `stack_top`. Pinned 128 MiB below
/// `USER_VA_TOP` so the reserve, guard hole, and ASLR slide all fit
/// within a comfortable ceiling while leaving headroom for future
/// per-thread stacks (pthread) and sigaltstack regions. ASLR slides the
/// stack downward from this anchor.
pub const STACK_TOP_ANCHOR: u64 = USER_VA_TOP - 0x0800_0000;

// ---- Canonical fixed VA windows (single source of truth) ----
//
// Every process maps the per-process windows — cap table, IPC buffer,
// ELF image, mmap window, DSO region, stack. init and mmsrv ALSO map
// their own self-VM windows (slab, segment, fault-stack). Because init
// and mmsrv are themselves processes, the union of all these windows must
// be mutually disjoint; this contract is the single place that guarantees
// it. The vfs pager-scratch window and the cap table were once both
// pinned at 0x6000_0000 in separate files with no shared check, so the
// first file-backed page-in mapped scratch onto the cap table and faulted
// (SIGSEGV). `assert_vm_windows_disjoint` rejects any such overlap at
// build time.

/// Read-only cap-table frame init maps in every child. The child's
/// substrate startup reads `AT_SALTYOS_STARTUP` to find it.
pub const CHILD_CAP_TABLE_VA: u64 = 0x0000_0000_6000_0000;
/// Reserved span for the cap-table window.
pub const CHILD_CAP_TABLE_LEN: u64 = 0x0000_0000_0010_0000;

/// vfs pager-scratch window: temporary mappings for the fresh `OBJ_FRAME`
/// caps the pager dispatcher hands to mmsrv. Sits in the free gap above
/// the mmap-window ceiling (`DEFAULT_CHILD_MMAP_LIMIT`) and below the
/// fault-dispatcher stack.
pub const PAGER_SCRATCH_VA_BASE: u64 = 0x0000_0000_4800_0000;
/// Reserved span for the pager-scratch window (64 MiB).
pub const PAGER_SCRATCH_VA_LEN: u64 = 0x0000_0000_0400_0000;

/// Per-process fault-dispatcher stack (init and mmsrv each map their own).
pub const FAULT_STACK_VA: u64 = 0x0000_0000_5000_0000;
/// Reserved span for the fault-dispatcher stack window.
pub const FAULT_STACK_LEN: u64 = 0x0000_0000_0100_0000;

/// init's private slab-backing self-VM window.
pub const INIT_SLAB_SCRATCH_BASE: u64 = 0x0000_0000_7000_0000;
/// Reserved span for init's slab window.
pub const INIT_SLAB_SCRATCH_LEN: u64 = 0x0000_0000_0400_0000;

/// mmsrv's cookie-table segment self-VM window.
pub const MMSRV_SEGMENT_SCRATCH_BASE: u64 = 0x0000_0000_8800_0000;
/// Reserved span for mmsrv's segment window.
pub const MMSRV_SEGMENT_SCRATCH_LEN: u64 = 0x0000_0000_0100_0000; // 16 MiB

/// mmsrv's slab-backing self-VM window (64 MiB live footprint cap).
pub const MMSRV_SLAB_SCRATCH_BASE: u64 = 0x0000_0000_9000_0000;
/// Reserved span for mmsrv's slab window.
pub const MMSRV_SLAB_SCRATCH_LEN: u64 = 0x0000_0000_0400_0000;

/// init's cookie-table segment self-VM window.
pub const INIT_SEGMENT_SCRATCH_BASE: u64 = 0x0000_0000_A000_0000;
/// Reserved span for init's segment window.
pub const INIT_SEGMENT_SCRATCH_LEN: u64 = 0x0000_0000_0100_0000; // 16 MiB

/// Default heap window registered for fresh service children. Mirror of the
/// historical init-local value; promoted here so init no longer carries a
/// parallel default and so the compile-time disjointness guard can check the
/// heap window against fixed mid-VA and DSO windows.
pub const DEFAULT_CHILD_HEAP_BASE: u64 = 0x0080_0000;
pub const DEFAULT_CHILD_HEAP_LIMIT: u64 = 0x0a00_0000;

/// Core-server heap window. Namesrv / rsrcsrv / mmsrv use this; their mmap
/// ceiling is narrower (`DEFAULT_CORE_MMAP_LIMIT`) than the child default so
/// the fixed mid-VA windows below stay disjoint.
pub const DEFAULT_CORE_HEAP_BASE: u64 = DEFAULT_CHILD_HEAP_BASE;
pub const DEFAULT_CORE_HEAP_LIMIT: u64 = DEFAULT_CHILD_HEAP_LIMIT;

/// Init's own heap window. Same range as the child default — init shares the
/// heap-window contract but uses a wider mmap ceiling (`DEFAULT_INIT_MMAP_LIMIT`).
pub const DEFAULT_INIT_HEAP_BASE: u64 = DEFAULT_CHILD_HEAP_BASE;
pub const DEFAULT_INIT_HEAP_LIMIT: u64 = DEFAULT_CHILD_HEAP_LIMIT;

/// Default per-child mmap-window base and ceiling. Core services run a
/// smaller ceiling (`0x3000_0000`); the fixed windows above must clear
/// the larger default so the mmsrv gap allocator — confined to
/// `[mmap_base, mmap_limit)` — can never hand out a colliding VA.
pub const DEFAULT_CHILD_MMAP_BASE: u64 = 0x0000_0000_2000_0000;
pub const DEFAULT_CHILD_MMAP_LIMIT: u64 = 0x0000_0000_4000_0000;

/// Core-server mmap ceiling — narrower than the child default so the fixed
/// mid-VA windows below stay disjoint.
pub const DEFAULT_CORE_MMAP_BASE: u64 = 0x0000_0000_2000_0000;
pub const DEFAULT_CORE_MMAP_LIMIT: u64 = 0x0000_0000_3000_0000;

/// Init's own mmap window. Uses the wider child ceiling because init owns the
/// pager-scratch dispatcher and needs the extra headroom.
pub const DEFAULT_INIT_MMAP_BASE: u64 = 0x0000_0000_2000_0000;
pub const DEFAULT_INIT_MMAP_LIMIT: u64 = 0x0000_0000_4000_0000;

/// Absolute runtime DSO ceiling. Each concrete plan lowers this to the
/// current stack reserve base (minus guard pages), so the DSO allocator can
/// never grow into that process's stack.
pub const DEFAULT_RUNTIME_DSO_BASE: u64 = DSO_LOAD_BASE_START;
pub const DEFAULT_RUNTIME_DSO_LIMIT: u64 = STACK_TOP_ANCHOR;

/// Base of the DSO / shared-library load region (grows upward by
/// `DSO_LOAD_BASE_STRIDE`). Every fixed window above must end below this.
pub const DSO_LOAD_BASE_START: u64 = 0x0000_4000_0000_0000;
/// Stride between successive DSO load bases.
pub const DSO_LOAD_BASE_STRIDE: u64 = 0x0000_0000_0400_0000;

/// The fixed VA windows — both low (heap, mmap) and mid (the self-managed
/// windows of init/mmsrv). Membership here is exactly what the compile-time
/// disjointness check covers — add new self-managed windows to this list so
/// the build rejects overlaps. Heap/mmap are low-VA and would fail a
/// `bi >= DEFAULT_CHILD_MMAP_LIMIT` check; pairwise overlap on this table
/// plus the `bi + li <= DSO_LOAD_BASE_START` ceiling check covers them.
const VM_FIXED_WINDOWS: [(u64, u64); 9] = [
    (
        DEFAULT_CHILD_HEAP_BASE,
        DEFAULT_CHILD_HEAP_LIMIT - DEFAULT_CHILD_HEAP_BASE,
    ),
    (
        DEFAULT_CHILD_MMAP_BASE,
        DEFAULT_CHILD_MMAP_LIMIT - DEFAULT_CHILD_MMAP_BASE,
    ),
    (PAGER_SCRATCH_VA_BASE, PAGER_SCRATCH_VA_LEN),
    (FAULT_STACK_VA, FAULT_STACK_LEN),
    (CHILD_CAP_TABLE_VA, CHILD_CAP_TABLE_LEN),
    (INIT_SLAB_SCRATCH_BASE, INIT_SLAB_SCRATCH_LEN),
    (MMSRV_SEGMENT_SCRATCH_BASE, MMSRV_SEGMENT_SCRATCH_LEN),
    (MMSRV_SLAB_SCRATCH_BASE, MMSRV_SLAB_SCRATCH_LEN),
    (INIT_SEGMENT_SCRATCH_BASE, INIT_SEGMENT_SCRATCH_LEN),
];

const fn ranges_overlap(b1: u64, l1: u64, b2: u64, l2: u64) -> bool {
    let e1 = b1 + l1;
    let e2 = b2 + l2;
    b1 < e2 && b2 < e1
}

/// Compile-time guard: every fixed window ends below the DSO region, and no
/// two fixed windows overlap. Pairwise overlap on `VM_FIXED_WINDOWS` covers
/// heap↔mmap, heap↔mid-VA, mmap↔mid-VA, and every mid-VA pair. The DSO-arena
/// ceiling check on each entry covers mmap↔DSO-arena (DSO_LOAD_BASE_START is
/// not in the table, so pairwise cannot catch it).
const fn assert_vm_windows_disjoint() {
    let n = VM_FIXED_WINDOWS.len();
    let mut i = 0;
    while i < n {
        let (bi, li) = VM_FIXED_WINDOWS[i];
        assert!(
            bi + li <= DSO_LOAD_BASE_START,
            "fixed VA window overlaps DSO region"
        );
        let mut j = i + 1;
        while j < n {
            let (bj, lj) = VM_FIXED_WINDOWS[j];
            assert!(
                !ranges_overlap(bi, li, bj, lj),
                "two fixed VA windows overlap"
            );
            j += 1;
        }
        i += 1;
    }
}

/// Top-level compile-time invariant: the runtime DSO arena must end below
/// the stack anchor so the stack reserve has room to grow without colliding
/// with the DSO arena. (DSO arena is not in `VM_FIXED_WINDOWS`, so pairwise
/// cannot enforce this.)
const _: () = assert!(
    DEFAULT_RUNTIME_DSO_LIMIT <= STACK_TOP_ANCHOR,
    "DSO arena collides with stack anchor"
);

const _: () = assert_vm_windows_disjoint();

/// Policy profile for child CSpace layout computation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CspaceLayoutProfile {
    DefaultService,
    Pager,
    BootstrapAuthority,
}

/// Compute the child CSpace layout contract.
///
/// `frame_slot_floor` is the first slot that must remain available for RTLD
/// frame allocation after fixed/service-injected slots. The returned
/// descriptor uses half-open ranges throughout.
pub fn compute_cspace_layout(
    cnode_bits: u64,
    frame_slot_floor: u64,
    profile: CspaceLayoutProfile,
    has_expand_window: bool,
) -> SaltyOSCspaceLayoutV1 {
    let total_slots = if cnode_bits >= 63 {
        0
    } else {
        1u64 << cnode_bits
    };

    let frame_slot_base = if frame_slot_floor > CHILD_FRAME_SLOT_BASE {
        frame_slot_floor
    } else {
        CHILD_FRAME_SLOT_BASE
    };

    let (expand_base, expand_limit) = if has_expand_window {
        let base = if total_slots > CSPACE_EXPAND_BASE {
            CSPACE_EXPAND_BASE
        } else {
            total_slots
        };
        let limit = {
            let requested = CSPACE_EXPAND_BASE + MAX_CSPACE_EXPANSIONS as u64;
            if total_slots < requested {
                total_slots
            } else {
                requested
            }
        };
        if limit > base { (base, limit) } else { (0, 0) }
    } else {
        (0, 0)
    };

    let (recv_base, recv_limit) = if total_slots != 0 {
        match profile {
            CspaceLayoutProfile::Pager | CspaceLayoutProfile::BootstrapAuthority => {
                let reserve = if total_slots > AUTHORITY_RECV_SLOT_COUNT {
                    AUTHORITY_RECV_SLOT_COUNT
                } else {
                    total_slots
                };
                (total_slots.saturating_sub(reserve), total_slots)
            }
            CspaceLayoutProfile::DefaultService => (0, 0),
        }
    } else {
        (0, 0)
    };

    // `alloc_base..alloc_limit` is the allocator envelope, not necessarily a
    // single contiguous pool: consumers subtract reserved holes such as the
    // CSpace-expansion window and the receive-slot range. The RTLD frame bump
    // allocator is still contiguous, so `frame_slot_limit` stops at the first
    // reserved hole.
    let mut alloc_limit = total_slots;
    if recv_limit > recv_base && recv_base < alloc_limit {
        alloc_limit = recv_base;
    }

    let mut frame_slot_limit = alloc_limit;
    if expand_limit > expand_base && expand_base < frame_slot_limit {
        frame_slot_limit = expand_base;
    }

    let alloc_base = if frame_slot_base < alloc_limit {
        frame_slot_base
    } else {
        alloc_limit
    };

    let mut flags = 0u64;
    if recv_limit > recv_base {
        flags |= SaltyOSCspaceLayoutV1::FLAG_HAS_RECV_RANGE;
    }
    if expand_limit > expand_base {
        flags |= SaltyOSCspaceLayoutV1::FLAG_HAS_EXPAND_RANGE;
    }

    SaltyOSCspaceLayoutV1 {
        version: SaltyOSCspaceLayoutV1::VERSION,
        flags,
        cnode_bits,
        rtld_untyped_base: CHILD_RTLD_UNTYPED_SLOT_START,
        rtld_untyped_count: CHILD_RTLD_UNTYPED_SLOT_END - CHILD_RTLD_UNTYPED_SLOT_START,
        // Producers (init) overwrite this after the call when
        // they know the actual mirrored untyped's size_bits.
        rtld_untyped_size_bits: 0,
        frame_slot_base,
        frame_slot_limit,
        alloc_base,
        alloc_limit,
        recv_base,
        recv_limit,
        expand_base,
        expand_limit,
    }
}

/// A contiguous page-aligned region in the child's virtual address space.
#[derive(Clone, Copy)]
pub struct VmRegion {
    /// Starting virtual address (page-aligned).
    pub base: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
}

impl VmRegion {
    /// An empty region (base=0, size=0).
    pub const fn zero() -> Self {
        VmRegion { base: 0, size: 0 }
    }
    /// Virtual address one byte past the end of this region.
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }
    /// Number of 4K pages in this region.
    pub const fn page_count(&self) -> usize {
        (self.size / 0x1000) as usize
    }
}

/// Per-process layout contract — every immutable window mmsrv needs to
/// enforce placement. Mutable cursors (`heap_current`, `mmap_hint`) live
/// alongside this in the mmsrv control record, but the base/limit
/// half-open ranges are fixed for the lifetime of the image.
///
/// `VmClientLayout` is the *wire* contract: `MM_REGISTER_CLIENT` and
/// `MM_BEGIN_EXEC_REPLACE` carry all twelve u64s. `VmLayoutPlan` is the
/// in-memory plan the planner produces; `VmLayoutPlan::client_layout()`
/// derives one of these.
///
/// Window ordering (low VA → high VA):
///   `heap_*` ⊂ low VA (above the code/scratch/initrd low-VA regions)
///   `mmap_*` ⊂ low VA (above `heap_limit`)
///   `dso_*`  ⊂ high VA (above the low-VA cap, up to `STACK_TOP_ANCHOR`)
///   `elf_code_*` ⊂ low VA (loader-stage for the main image)
///   `interpreter_*` ⊂ high DSO arena (loader-stage for the interpreter)
///   `preloaded_*`  ⊂ high DSO arena (loader-stage for DT_NEEDED)
/// Image windows may be zero-sized (static image with no interpreter / no
/// DT_NEEDED closure); `validate` accepts `base == limit == 0` for those.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VmClientLayout {
    pub heap_base: u64,
    pub heap_limit: u64,
    pub mmap_base: u64,
    pub mmap_limit: u64,
    pub dso_base: u64,
    pub dso_limit: u64,
    pub elf_code_base: u64,
    pub elf_code_limit: u64,
    pub interpreter_base: u64,
    pub interpreter_limit: u64,
    pub preloaded_base: u64,
    pub preloaded_limit: u64,
}

impl VmClientLayout {
    /// All-zero layout. Used as a sentinel / drop placeholder. Distinct from
    /// `validate` rejection: a zero layout is a programming error at the
    /// call site that produced it.
    pub const fn zero() -> Self {
        Self {
            heap_base: 0,
            heap_limit: 0,
            mmap_base: 0,
            mmap_limit: 0,
            dso_base: 0,
            dso_limit: 0,
            elf_code_base: 0,
            elf_code_limit: 0,
            interpreter_base: 0,
            interpreter_limit: 0,
            preloaded_base: 0,
            preloaded_limit: 0,
        }
    }

    /// Wire + runtime invariant validation. Called from every entry point
    /// that consumes a layout (mmsrv's `handle_register_client` and
    /// `handle_begin_exec_replace`) so a corrupted / untrusted wire value
    /// cannot poison client state.
    ///
    /// Required invariants:
    /// - `heap_base < heap_limit`, `mmap_base < mmap_limit`, `dso_base < dso_limit`
    /// - `heap_limit ≤ mmap_base` and `mmap_limit ≤ dso_base` (strict low-VA order)
    /// - `dso_base..dso_limit` lies inside the high DSO arena
    /// - `elf_code_base ≤ elf_code_limit` and `interpreter_base ≤ interpreter_limit`
    ///   and `preloaded_base ≤ preloaded_limit`, with equality meaning "no image"
    /// - When non-zero, image windows must lie inside their parent arena:
    ///   `elf_code` in low VA, `interpreter`/`preloaded` in the high DSO arena
    pub fn validate(&self) -> Result<(), LayoutError> {
        // The three allocator windows must be strictly ordered low→high.
        if self.heap_base >= self.heap_limit {
            return Err(LayoutError::InvalidHeapWindow);
        }
        if self.mmap_base >= self.mmap_limit {
            return Err(LayoutError::InvalidMmapWindow);
        }
        if self.dso_base >= self.dso_limit {
            return Err(LayoutError::InvalidDsoWindow);
        }
        if self.dso_base < DSO_LOAD_BASE_START || self.dso_limit > STACK_TOP_ANCHOR {
            return Err(LayoutError::InvalidDsoWindow);
        }
        if self.heap_limit > self.mmap_base {
            return Err(LayoutError::HeapMmapOverlap);
        }
        if self.mmap_limit > self.dso_base {
            return Err(LayoutError::MmapDsoOverlap);
        }
        // Image windows may be empty (size 0) for the static-image /
        // no-DT_NEEDED corner cases; both endpoints must agree so a
        // partially-populated wire value is rejected.
        if self.elf_code_base > self.elf_code_limit
            || (self.elf_code_base == 0) != (self.elf_code_limit == 0)
        {
            return Err(LayoutError::InvalidElfCodeWindow);
        }
        if self.interpreter_base > self.interpreter_limit
            || (self.interpreter_base == 0) != (self.interpreter_limit == 0)
        {
            return Err(LayoutError::InvalidInterpreterWindow);
        }
        if self.preloaded_base > self.preloaded_limit
            || (self.preloaded_base == 0) != (self.preloaded_limit == 0)
        {
            return Err(LayoutError::InvalidPreloadedWindow);
        }
        // Image windows must live inside their parent arena when non-empty:
        //   elf_code in low VA (below DSO_LOAD_BASE_START, the DSO arena base)
        //   interpreter / preloaded in high DSO arena ([DSO_LOAD_BASE_START,
        //   STACK_TOP_ANCHOR]) — aligned with `DEFAULT_RUNTIME_DSO_*`.
        if self.elf_code_limit > 0 && self.elf_code_limit > DSO_LOAD_BASE_START {
            return Err(LayoutError::ElfCodeOutOfLowArena);
        }
        if self.interpreter_limit > 0
            && (self.interpreter_base < DSO_LOAD_BASE_START
                || self.interpreter_limit > STACK_TOP_ANCHOR)
        {
            return Err(LayoutError::InterpreterOutOfDsoArena);
        }
        if self.preloaded_limit > 0
            && (self.preloaded_base < DSO_LOAD_BASE_START
                || self.preloaded_limit > STACK_TOP_ANCHOR)
        {
            return Err(LayoutError::PreloadedOutOfDsoArena);
        }
        Ok(())
    }
}

/// Result of computing or validating a per-process layout. Distinct error
/// variants so callers (init on exec, mmsrv on register) can surface a
/// precise cause to the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// `compute_vm_layout` could not place the heap window above the code
    /// region and below the mmap ceiling.
    HeapWindowEmpty,
    /// `compute_vm_layout` could not place the mmap window above the heap
    /// and below `DEFAULT_CHILD_MMAP_LIMIT`.
    MmapWindowEmpty,
    /// `compute_vm_layout` could not fit the runtime DSO window between the
    /// last preloaded image and `DEFAULT_RUNTIME_DSO_LIMIT`.
    RuntimeDsoWindowEmpty,
    /// Stack reserve overflowed the low-VA region.
    StackWindowEmpty,
    /// `VmClientLayout::validate` saw a malformed window (base >= limit or
    /// base/limit disagreement on the optional image windows).
    InvalidHeapWindow,
    InvalidMmapWindow,
    InvalidDsoWindow,
    InvalidElfCodeWindow,
    InvalidInterpreterWindow,
    InvalidPreloadedWindow,
    /// Two allocator windows were not strictly ordered.
    HeapMmapOverlap,
    MmapDsoOverlap,
    /// A non-empty image window lives outside its parent arena.
    ElfCodeOutOfLowArena,
    InterpreterOutOfDsoArena,
    PreloadedOutOfDsoArena,
}

impl LayoutError {
    pub fn wire_code(&self) -> u64 {
        use uapi::{KERNITE_ERR_INVALID_ARGUMENT, KERNITE_ERR_OUT_OF_RANGE};
        match self {
            // Construction-side "couldn't fit the plan" / "allocator
            // windows overlap" failures are caller-side layout bugs that
            // mean the caller picked an inconsistent layout — out-of-range.
            LayoutError::HeapWindowEmpty
            | LayoutError::MmapWindowEmpty
            | LayoutError::RuntimeDsoWindowEmpty
            | LayoutError::StackWindowEmpty
            | LayoutError::HeapMmapOverlap
            | LayoutError::MmapDsoOverlap => KERNITE_ERR_OUT_OF_RANGE as u64,
            // Malformed wire values (one end zero, the other non-zero; base
            // >= limit) and parent-arena violations are caller-side
            // argument-shape bugs — invalid argument.
            LayoutError::InvalidHeapWindow
            | LayoutError::InvalidMmapWindow
            | LayoutError::InvalidDsoWindow
            | LayoutError::InvalidElfCodeWindow
            | LayoutError::InvalidInterpreterWindow
            | LayoutError::InvalidPreloadedWindow
            | LayoutError::ElfCodeOutOfLowArena
            | LayoutError::InterpreterOutOfDsoArena
            | LayoutError::PreloadedOutOfDsoArena => KERNITE_ERR_INVALID_ARGUMENT as u64,
        }
    }
}

/// Complete virtual address layout for a child process.
///
/// Each field is a `VmRegion` describing a contiguous mapping. Regions with
/// `size == 0` are unused. `stack_top == 0` signals layout failure (code
/// regions overflow all available windows).
#[derive(Clone, Copy)]
pub struct VmLayoutPlan {
    /// IPC buffer page (1 page).
    pub ipc_buf: VmRegion,
    /// Cap-table frame window (every child reads `AT_SALTYOS_STARTUP` here).
    pub cap_table: VmRegion,
    /// ELF code/data segments.
    pub elf_code: VmRegion,
    /// Runtime dynamic linker (rtld). Zero-sized for static / PE images.
    pub interpreter: VmRegion,
    /// Preloaded DT_NEEDED closure (kernel32 for PE). Zero-sized when the
    /// interpreter resolves DT_NEEDED itself (path-exec).
    pub preloaded_dsos: VmRegion,
    /// Runtime DSO window: tail of the high-VA DSO arena reserved for
    /// image-reservation allocations by rtld. Static images still receive a
    /// non-empty window so mmsrv can register one uniform layout shape.
    pub runtime_dso_window: VmRegion,
    /// Heap window — `DEFAULT_CHILD_HEAP_BASE..DEFAULT_CHILD_HEAP_LIMIT`,
    /// adjusted by the planner so it starts above all low-VA code/scratch
    /// regions.
    pub heap_window: VmRegion,
    /// Anonymous mmap allocator window. mmsrv's gap allocator is confined
    /// to this range.
    pub mmap_window: VmRegion,
    /// User stack — usable reserve VmArea base and size. Guard hole and
    /// prefault sub-range are not included here; consult `stack_spec`
    /// for those. Size equals `stack_spec.reserve_pages * PAGE_SIZE`.
    pub stack: VmRegion,
    /// Scratch page for ELF loader page-copy operations.
    pub scratch: VmRegion,
    /// Initrd CPIO archive mapping window.
    pub initrd: VmRegion,
    /// Top of stack (initial RSP value).
    pub stack_top: u64,
    /// Per-service stack provisioning shape copied through fork so the
    /// child's `plan_stack_materialization` can reproduce the parent's
    /// reserve / prefault / guard coordinates without re-reading the
    /// manifest.
    pub stack_spec: StackLayoutSpec,
}

impl VmLayoutPlan {
    pub const fn zeroed() -> Self {
        VmLayoutPlan {
            ipc_buf: VmRegion { base: 0, size: 0 },
            cap_table: VmRegion { base: 0, size: 0 },
            elf_code: VmRegion { base: 0, size: 0 },
            interpreter: VmRegion { base: 0, size: 0 },
            preloaded_dsos: VmRegion { base: 0, size: 0 },
            runtime_dso_window: VmRegion { base: 0, size: 0 },
            heap_window: VmRegion { base: 0, size: 0 },
            mmap_window: VmRegion { base: 0, size: 0 },
            stack: VmRegion { base: 0, size: 0 },
            scratch: VmRegion { base: 0, size: 0 },
            initrd: VmRegion { base: 0, size: 0 },
            stack_top: 0,
            stack_spec: StackLayoutSpec::zeroed(),
        }
    }

    /// End of the highest code region
    /// (preloaded_dsos > interpreter > elf_code).
    pub fn code_end(&self) -> u64 {
        if self.preloaded_dsos.size > 0 {
            self.preloaded_dsos.end()
        } else if self.interpreter.size > 0 {
            self.interpreter.end()
        } else {
            self.elf_code.end()
        }
    }

    /// Highest end address across the *low-VA* regions (IPC buffer,
    /// cap_table, elf_code, scratch, initrd). Excludes the interpreter,
    /// preloaded_dsos, runtime_dso_window, heap/mmap windows and stack —
    /// those are anchored in the high DSO arena or in their own bands and
    /// would otherwise dominate the result.
    pub fn max_mapped_end(&self) -> u64 {
        let mut high = 0u64;
        let regions = [
            self.ipc_buf,
            self.cap_table,
            self.elf_code,
            self.scratch,
            self.initrd,
        ];
        for r in regions {
            if r.size == 0 {
                continue;
            }
            let end = r.end();
            if end > high {
                high = end;
            }
        }
        high
    }

    /// Derive the wire + runtime `VmClientLayout` from this plan. A zero-sized
    /// window maps to `base == limit == 0`; `validate` is the gate that
    /// rejects partially-populated wire values at the boundary. The cap_table,
    /// scratch, initrd, and stack regions are internal to the planner and are
    /// not exposed here — they are stamped into the child VSpace directly,
    /// not registered with mmsrv.
    ///
    /// All three image windows (`elf_code`, `interpreter`, `preloaded_dsos`)
    /// are included so mmsrv can validate exec staging against the same plan
    /// the loader used.
    pub fn client_layout(&self) -> VmClientLayout {
        let window_to_pair = |w: VmRegion| -> (u64, u64) {
            if w.size == 0 {
                (0, 0)
            } else {
                (w.base, w.end())
            }
        };
        let (heap_base, heap_limit) = window_to_pair(self.heap_window);
        let (mmap_base, mmap_limit) = window_to_pair(self.mmap_window);
        let (dso_base, dso_limit) = window_to_pair(self.runtime_dso_window);
        let (elf_code_base, elf_code_limit) = window_to_pair(self.elf_code);
        let (interpreter_base, interpreter_limit) = window_to_pair(self.interpreter);
        let (preloaded_base, preloaded_limit) = window_to_pair(self.preloaded_dsos);
        VmClientLayout {
            heap_base,
            heap_limit,
            mmap_base,
            mmap_limit,
            dso_base,
            dso_limit,
            elf_code_base,
            elf_code_limit,
            interpreter_base,
            interpreter_limit,
            preloaded_base,
            preloaded_limit,
        }
    }
}

/// Round up to the next 4K page boundary.
pub fn page_align_up(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFF
}

/// Compute the anonymous mmap window for a process. Returns
/// `[max(DEFAULT_CHILD_MMAP_BASE, collision-safe base), DEFAULT_CHILD_MMAP_LIMIT)`.
/// Returns `VmRegion::zero()` if the derived base >= limit (signals layout
/// construction failure to the caller).
pub fn compute_mmap_window(plan: &VmLayoutPlan) -> VmRegion {
    let heap_base = plan.heap_window.base;
    let high = core::cmp::max(plan.max_mapped_end(), heap_base);
    let derived = page_align_up(high.saturating_add(MMAP_BASE_GAP));
    let base = core::cmp::max(derived, DEFAULT_CHILD_MMAP_BASE);
    if base >= DEFAULT_CHILD_MMAP_LIMIT || base >= DSO_LOAD_BASE_START {
        return VmRegion::zero();
    }
    VmRegion {
        base,
        size: DEFAULT_CHILD_MMAP_LIMIT - base,
    }
}

/// Compute a dynamic VA layout for a child process.
///
/// Given the actual byte spans of the ELF, interpreter, and preloaded DSO
/// closure, plus the initrd window size, returns a complete layout plan.
/// Window collisions (heap overflowing mmap, mmap overflowing
/// `DEFAULT_CHILD_MMAP_LIMIT`, DSO arena overflowing its limit, or stack
/// overflowing the high-VA region) return a `LayoutError`.
///
/// Window placement:
/// - `elf_code` lives in low VA at `ELF_CODE_BASE`.
/// - `interpreter` and `preloaded_dsos` live in the high DSO arena
///   (`DSO_LOAD_BASE_START` and up), grown by `DSO_LOAD_BASE_STRIDE`.
///   This keeps the anonymous mmap / heap window as large as possible in
///   low VA and leaves the runtime tail where rtld expects image loads.
/// - `runtime_dso_window` follows the last preloaded DSO and runs up to the
///   per-plan DSO ceiling. Static images (no interpreter, no preloaded) start
///   the window at `DSO_LOAD_BASE_START` so the registered layout remains
///   valid and rtld receives explicit placement bounds.
/// - Heap window: starts above all low-VA code/scratch/initrd regions and
///   at least `DEFAULT_CHILD_HEAP_BASE`; ends at `DEFAULT_CHILD_HEAP_LIMIT`.
/// - mmap window: starts at the greater of `DEFAULT_CHILD_MMAP_BASE` and the
///   collision-safe derivation; ends at `DEFAULT_CHILD_MMAP_LIMIT`.
pub fn compute_vm_layout(
    elf_span: u64,
    interp_span: u64,
    preloaded_dso_spans: &[u64],
    map_initrd: bool,
    initrd_window_size: usize,
    stack_spec: StackLayoutSpec,
) -> Result<VmLayoutPlan, LayoutError> {
    let ipc_buf = VmRegion {
        base: IPC_BUF_BASE,
        size: 0x1000,
    };
    let cap_table = VmRegion {
        base: CHILD_CAP_TABLE_VA,
        size: CHILD_CAP_TABLE_LEN,
    };
    let elf_code = VmRegion {
        base: ELF_CODE_BASE,
        size: page_align_up(elf_span),
    };

    // Interpreter and preloaded DSOs live in the high DSO arena so the
    // anonymous mmap / heap window in low VA can grow up to
    // DEFAULT_CHILD_MMAP_LIMIT without colliding with code.
    let interpreter = if interp_span > 0 {
        let size = page_align_up(interp_span);
        if DSO_LOAD_BASE_START.checked_add(size).is_none() {
            return Err(LayoutError::RuntimeDsoWindowEmpty);
        }
        VmRegion {
            base: DSO_LOAD_BASE_START,
            size,
        }
    } else {
        VmRegion::zero()
    };

    let preloaded_dsos = if !preloaded_dso_spans.is_empty() && interpreter.size > 0 {
        let mut cursor = interpreter.end();
        let mut total = 0u64;
        for span in preloaded_dso_spans {
            let aligned_span = page_align_up(*span);
            total = total
                .checked_add(aligned_span)
                .and_then(|v| v.checked_add(DSO_LOAD_BASE_STRIDE))
                .ok_or(LayoutError::RuntimeDsoWindowEmpty)?;
        }
        // `total` is the sum-of-(span + stride); the final stride is unused,
        // so the actual span consumed is `total - DSO_LOAD_BASE_STRIDE`.
        let size = total.saturating_sub(DSO_LOAD_BASE_STRIDE);
        let base = page_align_up(cursor.saturating_add(DSO_LOAD_BASE_STRIDE));
        cursor = base
            .checked_add(size)
            .ok_or(LayoutError::RuntimeDsoWindowEmpty)?;
        VmRegion { base, size }
    } else {
        VmRegion::zero()
    };

    // Stack is anchored near the top of user VA. Reserve is `reserve_pages`
    // pages below `stack_top`; the unmapped guard hole sits below the
    // reserve and never appears as a VmArea.
    let stack_top = STACK_TOP_ANCHOR;
    let reserve_bytes = (stack_spec.reserve_pages as u64) * 0x1000;
    let guard_bytes = (stack_spec.guard_pages as u64) * 0x1000;
    if reserve_bytes == 0 {
        return Err(LayoutError::StackWindowEmpty);
    }
    let stack_base = stack_top
        .checked_sub(reserve_bytes)
        .ok_or(LayoutError::StackWindowEmpty)?;
    let stack_guard_bottom = stack_base
        .checked_sub(guard_bytes)
        .ok_or(LayoutError::StackWindowEmpty)?;
    if stack_guard_bottom <= DSO_LOAD_BASE_START {
        return Err(LayoutError::StackWindowEmpty);
    }
    let runtime_dso_limit = core::cmp::min(DEFAULT_RUNTIME_DSO_LIMIT, stack_guard_bottom);

    let runtime_dso_base = if preloaded_dsos.size > 0 {
        page_align_up(preloaded_dsos.end() + DSO_LOAD_BASE_STRIDE)
    } else if interpreter.size > 0 {
        page_align_up(interpreter.end() + DSO_LOAD_BASE_STRIDE)
    } else {
        DSO_LOAD_BASE_START
    };
    if runtime_dso_base >= runtime_dso_limit {
        return Err(LayoutError::RuntimeDsoWindowEmpty);
    }
    let runtime_dso_window = VmRegion {
        base: runtime_dso_base,
        size: runtime_dso_limit - runtime_dso_base,
    };

    // Scratch page for ELF loader staging — placed immediately after
    // the elf_code window in low VA (DSO arena is out of the way).
    let scratch = VmRegion {
        base: page_align_up(elf_code.end() + 0x1000),
        size: 0x1000,
    };

    let stack = VmRegion {
        base: stack_base,
        size: reserve_bytes,
    };

    let initrd = if map_initrd && initrd_window_size > 0 {
        let initrd_base = if scratch.end() > INITRD_BASE {
            page_align_up(scratch.end() + 0x1000)
        } else {
            INITRD_BASE
        };
        VmRegion {
            base: initrd_base,
            size: page_align_up(initrd_window_size as u64),
        }
    } else {
        VmRegion::zero()
    };

    // Heap window: starts above all low-VA code/scratch/initrd regions, ends
    // at the configured ceiling. Only low-VA regions participate (interp /
    // preloaded now sit in the high DSO arena).
    let heap_floor_raw = plan_max_low_mapped_end_for_heap(elf_code, scratch, initrd);
    let heap_floor = core::cmp::max(heap_floor_raw, DEFAULT_CHILD_HEAP_BASE);
    let heap_base = page_align_up(heap_floor);
    if heap_base >= DEFAULT_CHILD_HEAP_LIMIT {
        return Err(LayoutError::HeapWindowEmpty);
    }
    let heap_window = VmRegion {
        base: heap_base,
        size: DEFAULT_CHILD_HEAP_LIMIT - heap_base,
    };

    // mmap window computed from the now-final heap_window and the low-VA
    // ceiling. It must not reach the high DSO arena.
    let mmap_window = compute_mmap_window_for_heap(
        &heap_window,
        scratch.end().max(initrd.end()).max(elf_code.end()),
    );
    if mmap_window.size == 0 || mmap_window.base >= DSO_LOAD_BASE_START {
        return Err(LayoutError::MmapWindowEmpty);
    }

    Ok(VmLayoutPlan {
        ipc_buf,
        cap_table,
        elf_code,
        interpreter,
        preloaded_dsos,
        runtime_dso_window,
        heap_window,
        mmap_window,
        stack,
        scratch,
        initrd,
        stack_top,
        stack_spec,
    })
}

/// Highest end address across the *low-VA* regions (code, scratch, initrd).
/// Excludes the heap/mmap/runtime-dso windows and the stack region — those
/// are anchored in their own bands and would otherwise dominate the result.
/// Also excludes the high-DSO-arena interpreter and preloaded windows, which
/// no longer share a band with the heap.
fn plan_max_low_mapped_end_for_heap(
    elf_code: VmRegion,
    scratch: VmRegion,
    initrd: VmRegion,
) -> u64 {
    let mut high = 0u64;
    for r in [elf_code, scratch, initrd] {
        if r.size == 0 {
            continue;
        }
        let end = r.end();
        if end > high {
            high = end;
        }
    }
    high
}

fn compute_mmap_window_for_heap(heap: &VmRegion, low_va_high: u64) -> VmRegion {
    let high = core::cmp::max(low_va_high, heap.end());
    let derived = page_align_up(high.saturating_add(MMAP_BASE_GAP));
    let base = core::cmp::max(derived, DEFAULT_CHILD_MMAP_BASE);
    if base >= DEFAULT_CHILD_MMAP_LIMIT {
        return VmRegion::zero();
    }
    VmRegion {
        base,
        size: DEFAULT_CHILD_MMAP_LIMIT - base,
    }
}

/// Maximum ASLR slide for code base (in pages). 256 pages = 1 MiB entropy.
#[cfg(not(trona_disable_aslr))]
const ASLR_CODE_MAX_PAGES: u64 = 256;
/// Maximum ASLR slide for stack base (in pages). 64 pages = 256 KiB entropy.
#[cfg(not(trona_disable_aslr))]
const ASLR_STACK_MAX_PAGES: u64 = 64;

/// Compute a randomized VA layout for a child process (ASLR).
///
/// Applies random page-aligned offsets to the code base and stack base.
/// If `rand_u64` returns `None` (hardware RNG unavailable), falls back
/// to the deterministic layout.
///
/// `rand_u64` is a callback that returns a random u64.
pub fn compute_vm_layout_randomized(
    elf_span: u64,
    interp_span: u64,
    preloaded_dso_spans: &[u64],
    map_initrd: bool,
    initrd_window_size: usize,
    stack_spec: StackLayoutSpec,
    rand_u64: fn() -> Option<u64>,
) -> Result<VmLayoutPlan, LayoutError> {
    #[cfg(trona_disable_aslr)]
    {
        let _ = rand_u64;
        return compute_vm_layout(
            elf_span,
            interp_span,
            preloaded_dso_spans,
            map_initrd,
            initrd_window_size,
            stack_spec,
        );
    }

    #[cfg(not(trona_disable_aslr))]
    {
        // Get random offsets; fall back to 0 if RNG unavailable
        let code_slide = match rand_u64() {
            Some(v) => (v % ASLR_CODE_MAX_PAGES) * 0x1000,
            None => 0,
        };
        let stack_slide = match rand_u64() {
            Some(v) => (v % ASLR_STACK_MAX_PAGES) * 0x1000,
            None => 0,
        };

        let ipc_buf = VmRegion {
            base: IPC_BUF_BASE,
            size: 0x1000,
        };
        let cap_table = VmRegion {
            base: CHILD_CAP_TABLE_VA,
            size: CHILD_CAP_TABLE_LEN,
        };

        let code_base = ELF_CODE_BASE + code_slide;
        let elf_code = VmRegion {
            base: code_base,
            size: page_align_up(elf_span),
        };

        // Interpreter / preloaded DSOs live in the high DSO arena — see
        // compute_vm_layout for the rationale.
        let interpreter = if interp_span > 0 {
            let size = page_align_up(interp_span);
            VmRegion {
                base: DSO_LOAD_BASE_START,
                size,
            }
        } else {
            VmRegion::zero()
        };

        let preloaded_dsos = if !preloaded_dso_spans.is_empty() && interpreter.size > 0 {
            let mut total = 0u64;
            for span in preloaded_dso_spans {
                let aligned_span = page_align_up(*span);
                total = total
                    .checked_add(aligned_span)
                    .and_then(|v| v.checked_add(DSO_LOAD_BASE_STRIDE))
                    .ok_or(LayoutError::RuntimeDsoWindowEmpty)?;
            }
            let size = total.saturating_sub(DSO_LOAD_BASE_STRIDE);
            let base = page_align_up(interpreter.end() + DSO_LOAD_BASE_STRIDE);
            VmRegion { base, size }
        } else {
            VmRegion::zero()
        };

        let reserve_bytes = (stack_spec.reserve_pages as u64) * 0x1000;
        let guard_bytes = (stack_spec.guard_pages as u64) * 0x1000;
        if reserve_bytes == 0 {
            return Err(LayoutError::StackWindowEmpty);
        }
        let stack_top = STACK_TOP_ANCHOR
            .checked_sub(stack_slide)
            .ok_or(LayoutError::StackWindowEmpty)?;
        let stack_base = stack_top
            .checked_sub(reserve_bytes)
            .ok_or(LayoutError::StackWindowEmpty)?;
        let stack_guard_bottom = stack_base
            .checked_sub(guard_bytes)
            .ok_or(LayoutError::StackWindowEmpty)?;
        if stack_guard_bottom <= DSO_LOAD_BASE_START {
            return Err(LayoutError::StackWindowEmpty);
        }
        let runtime_dso_limit = core::cmp::min(DEFAULT_RUNTIME_DSO_LIMIT, stack_guard_bottom);

        let runtime_dso_base = if preloaded_dsos.size > 0 {
            page_align_up(preloaded_dsos.end() + DSO_LOAD_BASE_STRIDE)
        } else if interpreter.size > 0 {
            page_align_up(interpreter.end() + DSO_LOAD_BASE_STRIDE)
        } else {
            DSO_LOAD_BASE_START
        };
        if runtime_dso_base >= runtime_dso_limit {
            return Err(LayoutError::RuntimeDsoWindowEmpty);
        }
        let runtime_dso_window = VmRegion {
            base: runtime_dso_base,
            size: runtime_dso_limit - runtime_dso_base,
        };

        let scratch = VmRegion {
            base: page_align_up(elf_code.end() + 0x1000),
            size: 0x1000,
        };

        let stack = VmRegion {
            base: stack_base,
            size: reserve_bytes,
        };

        let initrd = if map_initrd && initrd_window_size > 0 {
            VmRegion {
                base: INITRD_BASE,
                size: page_align_up(initrd_window_size as u64),
            }
        } else {
            VmRegion::zero()
        };

        let heap_floor_raw = plan_max_low_mapped_end_for_heap(elf_code, scratch, initrd);
        let heap_floor = core::cmp::max(heap_floor_raw, DEFAULT_CHILD_HEAP_BASE);
        let heap_base = page_align_up(heap_floor);
        if heap_base >= DEFAULT_CHILD_HEAP_LIMIT {
            return Err(LayoutError::HeapWindowEmpty);
        }
        let heap_window = VmRegion {
            base: heap_base,
            size: DEFAULT_CHILD_HEAP_LIMIT - heap_base,
        };

        let mmap_window = compute_mmap_window_for_heap(
            &heap_window,
            scratch.end().max(initrd.end()).max(elf_code.end()),
        );
        if mmap_window.size == 0 || mmap_window.base >= DSO_LOAD_BASE_START {
            return Err(LayoutError::MmapWindowEmpty);
        }

        Ok(VmLayoutPlan {
            ipc_buf,
            cap_table,
            elf_code,
            interpreter,
            preloaded_dsos,
            runtime_dso_window,
            heap_window,
            mmap_window,
            stack,
            scratch,
            initrd,
            stack_top,
            stack_spec,
        })
    }
}
