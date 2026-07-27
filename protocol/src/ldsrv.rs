// SPDX-License-Identifier: GPL-2.0-only
//
//! ldsrv — code-loading authority wire protocol (block `0x0A00..=0x0A0F`).
//!
//! `ldsrv` is the steady-state minter of executable code MemoryObjects for
//! runtime processes: a consumer resolves a code object through one of the
//! resolve labels and receives a `READ|EXECUTE` code MO to map. The kernel's
//! cap-derived `max_prot` ceiling — not anything in this protocol — is the
//! W^X boundary; the register summaries below are advisory hints.
//!
//! Two resolution inputs, because a `DT_NEEDED` library and a program main
//! image are admitted differently:
//!
//! * [`LDSRV_RESOLVE_LIBRARY`] takes a soname; `ldsrv` owns the library
//!   namespace and resolves the name itself.
//! * [`LDSRV_RESOLVE_MAIN`] takes an already-opened **non-exec backing cap**:
//!   the caller has opened the image through the VFS under its own credential,
//!   so the `X_OK` / `MNT_NOEXEC` exec-permission policy stays with the
//!   caller. `ldsrv` never opens a main image by path.
//!
//! The adopt labels are the **private** PID 1 → `ldsrv` boot handoff and are
//! accepted only on `ldsrv`'s init-installed adopt channel
//! (`ROLE_LDSRV_ADOPT_RECV`), never on the name-service-published resolve
//! endpoint — so no public client can forge an adoption or steal the
//! exec-authority.
//!
//! Replies use [`crate::common::TRONA_OK`] as the label on success and the
//! error code as the label on failure (the project-wide server convention).

// --- resolve (public service endpoint) -----------------------------------

/// Resolve a `DT_NEEDED` shared library by soname. `ldsrv` owns the library
/// namespace and the search order (rootfs-authoritative once the rootfs is
/// mounted, with the initrd as bootstrap and fallback).
///
/// Request: `regs[LDSRV_RESOLVE_REQ_REG_NAME_LEN]` = soname byte length,
/// `regs[LDSRV_RESOLVE_REQ_NAME_BASE..]` = soname bytes packed 8 per word.
pub const LDSRV_RESOLVE_LIBRARY: u64 = 0x0A00;

/// Resolve a program **main image** that the caller has already opened through
/// the VFS under its own credential. `ldsrv` confers `EXECUTE` on the
/// presented non-exec backing and returns the code MO; it does not re-open by
/// path (which would bypass the caller's `X_OK` / `MNT_NOEXEC` check).
///
/// Request: `caps[0]` = the non-exec backing cap from `VFS_OPEN_FOR_EXEC`;
/// `regs[LDSRV_RESOLVE_MAIN_REQ_REG_SIZE]` = exact image byte size;
/// `regs[LDSRV_RESOLVE_MAIN_REQ_REG_OFFSET]` = image byte offset within the
/// backing MO.
pub const LDSRV_RESOLVE_MAIN: u64 = 0x0A01;

/// `LDSRV_RESOLVE_LIBRARY` request register indices.
pub const LDSRV_RESOLVE_REQ_REG_NAME_LEN: usize = 0;
/// First register of the packed soname bytes (8 bytes per word).
pub const LDSRV_RESOLVE_REQ_NAME_BASE: usize = 1;

/// `LDSRV_RESOLVE_MAIN` request register indices.
pub const LDSRV_RESOLVE_MAIN_REQ_REG_SIZE: usize = 0;
pub const LDSRV_RESOLVE_MAIN_REQ_REG_OFFSET: usize = 1;

// resolve reply — `caps[0]` = code MO (`READ|EXECUTE|GRANT|TRANSFER`). The
// register summary is an **advisory hint**: the consumer derives and validates
// its run plan from the code MO's own headers (mapped read-only), and the
// kernel cap-ceiling enforces W^X regardless of what the consumer does with
// the summary.
pub const LDSRV_RESOLVE_REPLY_REG_MO_SIZE: usize = 0;
/// Opaque 64-bit identity handle (the low word of the content digest) — for
/// consumer-side de-duplication and `dlclose` bookkeeping, not a trust token.
pub const LDSRV_RESOLVE_REPLY_REG_IDENTITY: usize = 1;
pub const LDSRV_RESOLVE_REPLY_REG_FORMAT: usize = 2;
pub const LDSRV_RESOLVE_REPLY_REG_ENTRY: usize = 3;
/// ELF program-header offset (advisory; 0 for non-ELF — read the headers from
/// the MO for PE).
pub const LDSRV_RESOLVE_REPLY_REG_PHOFF: usize = 4;
/// ELF program-header count (advisory; 0 for non-ELF).
pub const LDSRV_RESOLVE_REPLY_REG_PHNUM: usize = 5;
pub const LDSRV_RESOLVE_REPLY_REG_COUNT: u64 = 6;

/// `LDSRV_RESOLVE_REPLY_REG_FORMAT` values.
pub const LDSRV_FORMAT_ELF: u64 = 0;
pub const LDSRV_FORMAT_PE: u64 = 1;

// --- adopt (private init-only channel) -----------------------------------

/// PID 1 → `ldsrv`: adopt one boot code object into the cache.
///
/// ELF adopt uses a **borrowed-frames** code MO over the initrd bytes
/// (the file layout is also the memory layout, so byte 0 of the MO is
/// the ELF header).
///
/// PE adopt uses an **anonymous memory-image** code MO of `size_of_image`
/// bytes (the PE file's sections have been relayed from their file
/// offsets to their RVAs into a fresh memory-image MO before the R-X
/// conferral). The MO registers carry `LDSRV_ADOPT_REG_ENTRY = entry_rva`
/// and `LDSRV_ADOPT_REG_PHOFF = LDSRV_ADOPT_REG_PHNUM = 0` (PE has no
/// program-header table).
///
/// Both forms are accepted on the private adopt channel; the format
/// tag in `LDSRV_ADOPT_REG_FORMAT` selects how `ldsrv` interprets the
/// remaining registers. The registers carry the content-digest
/// identity, header summary, and soname so `ldsrv` reuses the same
/// MemoryObject identity (no recreation on first resolve).
pub const LDSRV_ADOPT_OBJECT: u64 = 0x0A02;

/// PID 1 → `ldsrv`: **move** the boot exec-authority capability to `ldsrv`, so
/// `EXECUTE` keeps a single origin and `ldsrv` becomes the steady-state
/// authority. `caps[0]` = the `ExecAuthority` cap. Private adopt channel only.
pub const LDSRV_ADOPT_AUTHORITY: u64 = 0x0A03;

/// PID 1 → `ldsrv`: seal adoption. `ldsrv` begins serving `resolve_*` and acks
/// PID 1, which only then spawns the first resolve client. Private adopt
/// channel only.
pub const LDSRV_ADOPT_SEAL: u64 = 0x0A04;

// `LDSRV_ADOPT_OBJECT` request register indices. The identity is a 128-bit
// content digest of the image bytes (the canonical key); the build-id / debug
// GUID is only a fast-path hint and never travels as the identity.
pub const LDSRV_ADOPT_REG_IDENTITY_LO: usize = 0;
pub const LDSRV_ADOPT_REG_IDENTITY_HI: usize = 1;
pub const LDSRV_ADOPT_REG_MO_SIZE: usize = 2;
pub const LDSRV_ADOPT_REG_FORMAT: usize = 3;
pub const LDSRV_ADOPT_REG_ENTRY: usize = 4;
pub const LDSRV_ADOPT_REG_PHOFF: usize = 5;
pub const LDSRV_ADOPT_REG_PHNUM: usize = 6;
pub const LDSRV_ADOPT_REG_NAME_LEN: usize = 7;
/// First register of the packed soname bytes (8 bytes per word).
pub const LDSRV_ADOPT_NAME_BASE: usize = 8;

// --- content identity ----------------------------------------------------

/// Canonical code-object identity: a 128-bit content digest of the image
/// bytes. This is the **contract** between PID 1 (which digests the
/// contiguous initrd bytes at the Stage-1 handoff) and `ldsrv` (which
/// digests a VFS-resolved object by streaming its read-only backing) — the
/// two must agree byte-for-byte, so the algorithm lives here, shared.
///
/// It is a fast non-cryptographic 128-bit hash for de-duplication, not an
/// integrity/attestation signature: the W^X trust boundary is the kernel's
/// cap-derived ceiling, and the bytes hashed *are* the object, so a
/// content-distinct artifact necessarily yields a distinct identity. Stream
/// it with [`ContentDigest::update`]; the inputs need not be page-aligned or
/// arrive in fixed chunks — only the concatenated byte sequence matters.
#[derive(Clone, Copy)]
pub struct ContentDigest {
    lo: u64,
    hi: u64,
}

const LDSRV_FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const LDSRV_FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

impl Default for ContentDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentDigest {
    pub const fn new() -> Self {
        Self {
            lo: LDSRV_FNV_OFFSET,
            hi: 0x9e37_79b9_7f4a_7c15,
        }
    }

    /// Fold `bytes` into the running digest. Two decorrelated 64-bit lanes:
    /// `lo` is plain FNV-1a; `hi` rotates and mixes in `lo` so the two halves
    /// do not move in lockstep.
    pub fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.lo = (self.lo ^ b as u64).wrapping_mul(LDSRV_FNV_PRIME);
            self.hi = (self.hi.rotate_left(7) ^ b as u64)
                .wrapping_mul(LDSRV_FNV_PRIME)
                .wrapping_add(self.lo);
        }
    }

    /// Finish the digest into its `(lo, hi)` 128-bit value.
    pub const fn finish(self) -> (u64, u64) {
        (self.lo, self.hi)
    }
}
