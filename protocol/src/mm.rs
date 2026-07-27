// SPDX-License-Identifier: GPL-2.0-only
//
//! mmsrv server wire (block 0x400..=0x4FF). Self-tier labels
//! (`MM_MMAP / MUNMAP / MPROTECT / BRK / SBRK / SHM_* / FILE_MMAP /
//! PREFAULT_RANGE / GET_SYSTEM_MEMINFO`) live at 0x410..=0x4F0.
//! init-only / cross-client labels (`MM_REGISTER_CLIENT /
//! _DEREGISTER_CLIENT / _FORK_VSPACE / _REGISTER_FAULT_PIPE /
//! _RESERVE_RANGE / _UNRESERVE_RANGE / _BIND_CLIENT_SELF /
//! _STAGE_IMAGE_REGION / _BEGIN_EXEC_REPLACE / _COMMIT_EXEC_REPLACE /
//! _ABORT_EXEC_REPLACE`) live at 0x400..=0x40F (admin tier with the
//! single bootstrap-bind exception of `MM_BIND_CLIENT_SELF` at 0x408).

// init-only / cross-client tier (0x400..=0x40F).

/// `MM_REGISTER_CLIENT(client_id, vspace, request_mp_recv,
/// request_mp_send)`: init registers a new mmsrv client. Caller is
/// init only (badge gate). request_mp_recv / send caps both flow
/// through `caps[]` so mmsrv can route self-tier replies back to the
/// per-client MP_CORE pair without re-acquiring the cap.
pub const MM_REGISTER_CLIENT: u64 = 0x400;
pub const MM_DEREGISTER_CLIENT: u64 = 0x401;
pub const MM_FORK_VSPACE: u64 = 0x402;
pub const MM_REGISTER_FAULT_PIPE: u64 = 0x403;
pub const MM_STAGE_IMAGE_REGION: u64 = 0x404;
pub const MM_BEGIN_EXEC_REPLACE: u64 = 0x405;
pub const MM_COMMIT_EXEC_REPLACE: u64 = 0x406;
pub const MM_ABORT_EXEC_REPLACE: u64 = 0x407;

/// Two-operand verb step 1: pin the *secondary* operand of a
/// two-operand admin verb. A control cap surfaces its badge
/// only on invoke, so the second operand of `MM_FORK_VSPACE` (the child)
/// and the cross-client `MM_STAGE_IMAGE_REGION` (the source) cannot ride
/// as a transferred cap — it is established by a prior invoke of that
/// operand's own control cap. `MM_FORK_SET_PARTNER(nonce)` invoked on the
/// child's control cap records `pending{secondary_slot, secondary_epoch,
/// nonce}`; the matching `MM_FORK_VSPACE(nonce, ...)` invoked on the
/// parent's control cap then consumes it.
pub const MM_FORK_SET_PARTNER: u64 = 0x409;
/// Two-operand verb step 1 for cross-client `MM_STAGE_IMAGE_REGION`:
/// `MM_STAGE_SET_SOURCE(nonce)` invoked on the source client's control
/// cap records the pending source operand; the destination's
/// `MM_STAGE_IMAGE_REGION(nonce, ...)` consumes it. The `EXEC_MO_SRC`
/// sub-path has no source *client*, so it takes no partner step.
pub const MM_STAGE_SET_SOURCE: u64 = 0x40D;

/// `MM_STAGE_IMAGE_REGION` `flags` bit 0: route the destination
/// mapping into the client's pending exec VSpace. The transaction id
/// rides in the high 32 bits of the same flags word.
pub const STAGE_FLAG_EXEC_TXN: u64 = 1 << 0;
/// `MM_STAGE_IMAGE_REGION` `flags` bit 1: preserve the destination
/// mapping as a user stack VMA (`KERNITE_REGION_KIND_STACK`).
pub const STAGE_FLAG_STACK: u64 = 1 << 1;
/// `MM_STAGE_IMAGE_REGION` `flags` bit 2: the staged region's source is
/// the forwarded exec MemoryObject held in the pending exec transaction
/// (set by `MM_BEGIN_EXEC_REPLACE`), so no `src_region_id` is passed.
/// Used by execve image staging; mmsrv maps a page-aligned, read-only run
/// as a shared sub-range of that MO (zero-copy), while writable, page-
/// shared, or non-page-aligned runs are staged as a private COW copy via
/// `STAGE_FLAG_EXEC_MATERIALIZE`.
pub const STAGE_FLAG_EXEC_MO_SRC: u64 = 1 << 2;
/// `MM_STAGE_IMAGE_REGION` `flags` bit 3 (only meaningful with
/// `STAGE_FLAG_EXEC_MO_SRC`): the run cannot be shared zero-copy (it is
/// page-shared by segments with different protections, starts/ends mid-
/// page, or is writable), so mmsrv stages it as a private copy — it clones
/// the run's file pages out of the exec MemoryObject into an anonymous COW
/// child and zero-fills the tail beyond the file content, instead of
/// mapping the MO sub-range shared. The `regs[9]` image kind still selects
/// the region type / `max_prot` (a materialised TEXT run stays
/// `REGION_IMAGE_TEXT`, never writable). The loader sets it per run for
/// boundary / page-shared / writable segments and clears it for the
/// zero-copy page-aligned interior.
pub const STAGE_FLAG_EXEC_MATERIALIZE: u64 = 1 << 3;
/// `MM_STAGE_IMAGE_REGION` `flags` bit 4: the staged region's source is a
/// caller-provided code MemoryObject transferred as `caps[0]` (not the pending
/// exec transaction's MO), staged into the destination client's live VSpace.
/// Used to map a service's interpreter / library closure run-by-run from a
/// `READ|EXECUTE` code MO (minted by the bootstrap loader, or resolved by
/// `ldsrv`) so executable text never originates from an anonymous copy. The
/// `regs[9]` image kind and `STAGE_FLAG_EXEC_MATERIALIZE` select the run type /
/// sharing exactly as for `STAGE_FLAG_EXEC_MO_SRC`.
pub const STAGE_FLAG_PROVIDED_MO: u64 = 1 << 4;
pub const STAGE_FLAG_TXN_ID_SHIFT: u32 = 32;
/// `MM_STAGE_IMAGE_REGION` flags: a stack's guard width in **pages**,
/// packed into bits `[15:8]` of the flags word and only meaningful with
/// `STAGE_FLAG_STACK`. The loader sets it from its `guard_pages` so mmsrv
/// reserves a matching-width guard band below the stack; `0` = no guard.
pub const STAGE_GUARD_PAGES_SHIFT: u32 = 8;
pub const STAGE_GUARD_PAGES_MASK: u64 = 0xFF;

/// `MM_STAGE_IMAGE_REGION` `regs[9]` — image-segment classification for
/// the staged region. mmsrv stamps the matching `REGION_IMAGE_*` /
/// `SHARED_LIB` kind and image-aware backing / fork metadata: `TEXT` /
/// `RODATA` are read-only and shared into a forked child, while `DATA` /
/// `BSS` are copy-on-write like an anonymous region. The concrete backing
/// descriptor depends on the source path (shared provided-MO regions retain a
/// file/code-MO cap; registry-owned materialised or zero-fill regions use image
/// metadata). `NONE` stages an anonymous (non-image) region — used for
/// cap-table / IPC scratch. Ignored when `STAGE_FLAG_STACK` is set. The ELF /
/// PE loaders derive the kind from each run's protection (exec → `TEXT`,
/// writable → `DATA`, read-only → `RODATA`); a segment's zero-fill tail is
/// materialised into its writable run, so it carries the `DATA` kind.
pub const STAGE_IMAGE_KIND_NONE: u64 = 0;
pub const STAGE_IMAGE_KIND_TEXT: u64 = 1;
pub const STAGE_IMAGE_KIND_DATA: u64 = 2;
pub const STAGE_IMAGE_KIND_RODATA: u64 = 3;
pub const STAGE_IMAGE_KIND_BSS: u64 = 4;

/// Bootstrap-bind exception inside the admin-tier block — child
/// resolves its own self-tier MP send cap by calling this label
/// against the master service-EP. mmsrv looks up `client_id` from
/// the `client_table` and copies the stored `request_mp_send_slot`
/// into the caller's receive slot.
pub const MM_BIND_CLIENT_SELF: u64 = 0x408;

/// `MM_RESERVE_RANGE(base, length, kind)`: reserve a VA range in the
/// **caller's own** VM (self-tier — the caller reserves its own arena
/// holes; init reserves its own fixed scratch windows). `kind` is a
/// `ReservationKind` discriminant (`Arena=0`, `Guard=1`, `Exclusion=2`,
/// `System=3`). Reply: `regs[0]=idx, regs[1]=generation`.
/// `MM_UNRESERVE_RANGE(base)` drops the reservation covering `base`.
/// (Values sit in the 0x40x block for historical reasons but route
/// through the per-client request MP, not the admin service-EP.)
pub const MM_RESERVE_RANGE: u64 = 0x40A;
pub const MM_UNRESERVE_RANGE: u64 = 0x40B;

/// `MM_ALLOC_RANGE(length, align, bounds_lo, bounds_hi, kind)`: choose a
/// free VA range of `length` (aligned to `align`; page-default when zero)
/// inside `[bounds_lo, bounds_hi)` in the caller's own VM and reserve it.
/// mmsrv picks the base, so the result is collision-free by construction —
/// unlike the fixed-base `MM_RESERVE_RANGE`. Reply: `regs[0]` = chosen base
/// VA, `regs[1]` = packed `ReservationId`.
pub const MM_ALLOC_RANGE: u64 = 0x40C;

/// `kind` discriminant for `MM_RESERVE_RANGE` / `MM_ALLOC_RANGE`: a
/// server-managed system reservation. Must match `ReservationKind::System`
/// in `trona_server::slab`.
pub const MM_RESERVATION_KIND_SYSTEM: u64 = 3;

// self-tier (0x410..=0x4F0).

/// `MM_MMAP` `kind` discriminants. The kind selects the
/// `BackingDescriptor` variant mmsrv stamps onto the resulting
/// `MappedRegion` — `MMAP_KIND_ANON` / `_ANON_STACK` allocate fresh
/// anonymous MOs, `_SHARED_ANON` and `_DEVICE` are reserved for the
/// future shm-via-mmap and device-mapping paths, and `_MO` consumes a
/// caller-supplied MO cap (typically a pager-attached MO returned by
/// `VFS_GET_BACKING_MO`).
pub const MMAP_KIND_ANON: u64 = 0;
pub const MMAP_KIND_ANON_STACK: u64 = 1;
pub const MMAP_KIND_SHARED_ANON: u64 = 2;
pub const MMAP_KIND_DEVICE: u64 = 3;
pub const MMAP_KIND_MO: u64 = 4;
/// shm-backed MO mapping. Same wire shape as `MMAP_KIND_MO` (a caller-supplied
/// MO cap plus `mo_offset`), but tells mmsrv the backing is a pager-less shm
/// object rather than a file. The two diverge only under `MM_FLAG_PRIVATE`: a
/// private shm mapping is a strict Zircon-style snapshot — mmsrv freezes the
/// shared object into a hidden parent so the private child reads the frozen
/// pages and breaks on write — whereas a private file mapping is a lazy COW
/// clone whose child resolves uncommitted pages through the file's pager. A
/// shared mapping (no `MM_FLAG_PRIVATE`) maps both kinds identically: the
/// shared object itself. VFS stamps this kind on the `VFS_GET_BACKING_MO`
/// reply for POSIX shm fds; file fds keep `MMAP_KIND_MO`.
pub const MMAP_KIND_SHM_MO: u64 = 5;

/// `MM_MMAP` / `MM_FILE_MMAP` `flags` word bits (`regs[4]`). These are the
/// wire flags the client packs and mmsrv unpacks; they live here as the
/// single source of truth so the two ends cannot drift.
pub const MM_FLAG_FIXED: u64 = 1 << 0;
pub const MM_FLAG_GROWSDOWN: u64 = 1 << 1;
pub const MM_FLAG_LAZY: u64 = 1 << 2;
/// Private (copy-on-write) mapping of a caller-supplied MO, set from POSIX
/// `MAP_PRIVATE`; its absence means a shared mapping. mmsrv privatises the
/// backing per `kind`: `MMAP_KIND_SHM_MO` takes the `MO_SNAPSHOT` (strict
/// snapshot) path, `MMAP_KIND_MO` the `MO_CLONE` (lazy pager-through COW) path.
pub const MM_FLAG_PRIVATE: u64 = 1 << 3;
/// Fixed-placement mapping that must fail rather than replace when the
/// requested range collides with an existing mapping or reservation.
pub const MM_FLAG_FIXED_NOREPLACE: u64 = 1 << 4;

/// `MM_MMAP(kind, hint, length, prot, flags, mo_offset; caps=[mo_cap?])
/// -> (mapped_va, region_idx, region_epoch)`. BackingDescriptor-unified
/// mmap entry. `kind` selects the backing variant:
///
/// * `MMAP_KIND_ANON` (`0`) — anonymous private mapping. mmsrv retypes a
///   fresh anon MO out of its frame pool. caps unused.
/// * `MMAP_KIND_ANON_STACK` (`1`) — anonymous stack region (same MO
///   semantics as ANON, different `region_kind` annotation).
/// * `MMAP_KIND_MO` (`4`) — caller-supplied MO mapping. `caps[0]` is the
///   MO cap (typically obtained from `VFS_GET_BACKING_MO` for
///   file-backed pager mappings, or `MM_SHM_*` for shm). `regs[5]` is
///   the page offset within the MO. mmsrv invokes
///   `KERNITE_INV_VSPACE_MAP_MO` to install the MO at `hint` (or an
///   auto-placed VA when `MAP_FIXED` is unset).
///
/// File-backed mmap is a two-step client flow: `VFS_GET_BACKING_MO`
/// first (vfs miss issues `MM_FILE_MMAP` to mmsrv internally to retype
/// the MO and attach the pager), then `MM_MMAP(kind=MO, caps[0]=mo_cap,
/// mo_offset)` to land the MO in the caller's vspace. mmsrv self-tier
/// never accepts a target client other than the caller — the MO cap is
/// the unforgeable token of access.
pub const MM_MMAP: u64 = 0x410;
/// `MM_MMAP` `regs[6]` — optional image-reservation id (`0` = none). When
/// non-zero it names an `Image`-purpose reservation in the caller's own VM
/// (from `MM_RESERVE_IMAGE`); the mapping must be `MM_FLAG_FIXED` and lie
/// fully within that reservation, and mmsrv tags the resulting region with it
/// so `MM_UNMAP_IMAGE` tears the whole image down as a unit. `regs[7]` must
/// then carry the segment classification (`STAGE_IMAGE_KIND_*`) so the
/// self-tier dynamic-linker path preserves the same region type, max-prot,
/// backing descriptor, and fork policy as the init-stage
/// `MM_STAGE_IMAGE_REGION` path. The dynamic linker places each attenuated run
/// (text `R-X` / rodata `R--` / data COW `R-W` / bss zero-fill) of a resolved
/// code object into one such envelope.
pub const MM_MMAP_REQ_REG_IMAGE_ID: usize = 6;
/// `MM_MMAP` `regs[7]` — image run kind paired with
/// [`MM_MMAP_REQ_REG_IMAGE_ID`]. `STAGE_IMAGE_KIND_NONE` is valid only when
/// `regs[6] == 0`.
pub const MM_MMAP_REQ_REG_IMAGE_KIND: usize = 7;
/// `MM_MMAP` `regs[8]` — file-backed VFS mo binding id returned by
/// `VFS_GET_BACKING_MO`. Non-zero only for `MMAP_KIND_MO` mappings that VFS
/// can write back through its pager/page-cache ownership.
pub const MM_MMAP_REQ_REG_FILE_BACKING_ID: usize = 8;
/// `MM_MMAP` `regs[9]` — byte length of the file-backed binding returned by
/// `VFS_GET_BACKING_MO`, used to clamp writeback ranges at the VFS layer.
pub const MM_MMAP_REQ_REG_FILE_BACKING_LENGTH: usize = 9;
pub const MM_MUNMAP: u64 = 0x411;
pub const MM_MPROTECT: u64 = 0x412;
pub const MM_BRK: u64 = 0x413;
pub const MM_SBRK: u64 = 0x414;
pub const MM_MSYNC: u64 = 0x418;
/// VFS -> mmsrv async completion for an explicit MAP_SHARED writeback
/// request. mmsrv stamps a low-range request token into `VFS_MSYNC_MO`;
/// VFS sends this record on its ordinary mmsrv client endpoint after every
/// dirty page in that range has either reached the backend or failed.
/// `regs[0]=request_token`, `regs[1]=VFS_PUBLIC_REPLY_* status`.
pub const MM_VFS_WRITEBACK_DONE: u64 = 0x419;
/// `MM_MO_CREATE(length, flags) -> (caps=[mo_cap])` — self-tier
/// label: caller asks mmsrv to retype a fresh anonymous MO out of
/// its frame pool and return the cap. The MO is `length` bytes
/// rounded up to PAGE granularity; mmsrv stamps the caller's
/// `client_idx` as the owner so the MO is reclaimed when the
/// client exits. Used by callers that need a transient MO to
/// transfer payload via `caps[0]` on a downstream RPC (e.g. the
/// `TRANSFER_KIND_MO` path of `BACKEND_WRITE`) and then drop the
/// cap. `flags` is reserved (must be zero today).
pub const MM_MO_CREATE: u64 = 0x415;
/// `MM_RESERVE_IMAGE(base, bytes) -> (image_id)` — reserve a contiguous load
/// envelope for an image in the caller's own VSpace; the returned packed
/// `ReservationId` is the image's teardown handle for `MM_UNMAP_IMAGE`.
pub const MM_RESERVE_IMAGE: u64 = 0x416;
/// `MM_UNMAP_IMAGE(image_id)` — unmap every region tagged with the image
/// reservation `image_id`, release their backings, and free the reservation.
pub const MM_UNMAP_IMAGE: u64 = 0x417;
pub const MM_SHM_CREATE: u64 = 0x420;
pub const MM_SHM_MAP: u64 = 0x421;
pub const MM_SHM_DESTROY: u64 = 0x422;
pub const MM_SHM_UNMAP: u64 = 0x423;
/// `MM_FILE_MMAP(vnode_slot, vnode_epoch, file_handle, file_offset,
/// length, prot, flags) -> (mo_idx, mo_id; caps=[mo_cap])` — **vfs-only
/// MO materialise label**. Not part of the client-facing mmap path:
/// clients never call this directly. vfs invokes it from
/// `VFS_GET_BACKING_MO` miss handling to retype a file-backed MO bound
/// to its previously-registered pager. mmsrv retypes the MO out of its
/// frame pool, invokes `MO_ATTACH_PAGER(mo_cap, vfs_pager_cap_slot)`
/// so the kernel can route page-absent faults to vfs's event queue,
/// installs the `(vnode_slot, vnode_epoch, mo_id)` binding into its
/// `file_backed_registry`, and replies with the MO cap copy + the
/// kernel-issued `mo_id`. mmsrv enforces that the caller's `client_idx`
/// matches the client that registered the pager via
/// `MM_REGISTER_VFS_PAGER` — a non-pager-owner caller receives
/// `KERNITE_ERR_INSUFFICIENT_RIGHTS`. Clients land the MO in their own
/// vspace through `MM_MMAP(kind=MO, caps[0]=mo_cap)`; faults on absent
/// pages flow through `KERNITE_EVENT_TYPE_PAGER_REQUEST` events
/// delivered directly to vfs (mmsrv is not on the fault path).
pub const MM_FILE_MMAP: u64 = 0x430;
pub const MM_PREFAULT_RANGE: u64 = 0x440;
/// `MM_REGISTER_VFS_PAGER(; caps=[pager_cap, writeback_mp_send])` —
/// vfs registers its `OBJ_PAGER` capability and its mmsrv-private
/// writeback request channel. mmsrv stores the caps in
/// `ServerState.vfs_pager_cap_slot` / `vfs_writeback_mp_send_slot`
/// and stamps the caller's `client_idx` into
/// `vfs_pager_owner_client_idx` so subsequent `MM_FILE_MMAP` callers
/// can be checked against the pager owner — only the registered owner
/// (vfs) is permitted to materialise file-backed MOs. Every
/// `MM_FILE_MMAP` invokes `MO_ATTACH_PAGER(mo_cap, vfs_pager_cap)`
/// against the stored cap so the kernel routes page-absent faults
/// through the pager's bound EventQueue, bypassing mmsrv on the fault
/// path. `MM_MSYNC`/file-backed `MM_MUNMAP` use the writeback channel
/// to ask vfs to flush resident dirty MO pages through its normal
/// page-cache/backend path. First-write-wins (returns
/// `KERNITE_ERR_ALREADY_EXISTS` on repeat).
pub const MM_REGISTER_VFS_PAGER: u64 = 0x441;
pub const MM_GET_SYSTEM_MEMINFO: u64 = 0x4F0;
/// Cumulative committed virtual address space across every live
/// region, in bytes. Reply: `regs[0] = committed_as_bytes`.
pub const MM_GET_COMMIT_AS: u64 = 0x4F1;

/// Per-process memory snapshot for procfs (gated to the vfs pager
/// owner). `regs[0]=pid`; reply packs a `TronaProcMemSnapshot` (20
/// `u64`) into `regs[0..20]` — fits one MP record, no `reserved[]`
/// bulk channel. mmsrv glues the kernel `VSPACE_GET_MEM_STATS` to its
/// own heap / region metadata. Backs `/proc/<pid>/{stat,status,statm}`.
pub const MM_GET_CLIENT_VM_STATS: u64 = 0x4F2;
/// Walk a client's VMA list. `regs[0]=pid`, `regs[1]=offset`.
/// Reply: `regs[0]=count_returned`, entries pack into the IPC
/// buffer's `reserved[]` area as `MmsrvVmaEntry` records. Used by
/// `/proc/<pid>/{maps,smaps}`.
pub const MM_LIST_VMAS: u64 = 0x4A0;
/// Walk a client's reservation list. `regs[0]=pid`. Reply:
/// `regs[0]=count_returned`, entries pack into the IPC buffer's
/// `reserved[]` area as reservation records (`base`, `length`,
/// `owner_badge`, `kind`). `owner_badge == 0` marks an unowned exclusion
/// zone (e.g. the null guard). Gated to the vfs pager owner; used by
/// `/proc/<pid>/reservations`.
pub const MM_LIST_RESERVATIONS: u64 = 0x4A1;
