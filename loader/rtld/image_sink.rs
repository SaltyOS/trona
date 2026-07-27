// SPDX-License-Identifier: GPL-2.0-only
//! Self-mapping [`PlacementSink`] for the runtime linker.
//!
//! The linker resolves a code MemoryObject from `ldsrv` and maps its runs into
//! its OWN address space, inside an mmsrv image reservation so `dlclose` can
//! tear the whole image down as a unit. Each run is mapped through a
//! rights-attenuated alias of the code MO that the linker mints itself — it
//! holds the full `READ|EXECUTE|GRANT|TRANSFER` cap, so narrowing it to a
//! per-run alias grants no authority it does not already have. Text maps `R-X`,
//! rodata `R--`, writable data a private copy-on-write child `R-W`, and `.bss`
//! private zero-fill. The kernel's cap-derived ceiling — not this code — is the
//! W^X boundary.

use crate::common::image::{
    Carve, ImageEnvelope, ImageId, ImageIdKind, ImageRunKind, PROT_WRITE, PlacementSink, Run,
    RunPlan, RunSource, map_image,
};
use trona_kernel::core_types::CapRef;
use trona_protocol::mm::{
    STAGE_IMAGE_KIND_BSS, STAGE_IMAGE_KIND_DATA, STAGE_IMAGE_KIND_RODATA, STAGE_IMAGE_KIND_TEXT,
};
use trona_runtime::client::mm;
use trona_runtime::core::slot_alloc::dup_for_transfer_with_rights;

const PAGE: u64 = 4096;

/// Why realizing a code image into the linker's own address space failed.
#[derive(Clone, Copy, Debug)]
pub enum SinkError {
    /// `MM_RESERVE_IMAGE` failed (no room for the load envelope).
    Reserve,
    /// Minting a rights-attenuated per-run alias of the code MO failed.
    Alias,
    /// Mapping one run into the image envelope failed.
    MapRun,
}

/// Rights for the per-run alias minted from the code MO. All aliases keep
/// `GRANT` so mmsrv can re-duplicate the region backing across `fork`, and
/// `TRANSFER` so the alias can ride the `MM_MMAP` cap transfer.
fn alias_rights(kind: ImageRunKind) -> u64 {
    let base = uapi::KERNITE_RIGHT_READ as u64
        | uapi::KERNITE_RIGHT_GRANT as u64
        | uapi::KERNITE_RIGHT_TRANSFER as u64;
    match kind {
        // Text keeps EXECUTE so the run maps `R-X`; the kernel ceiling then
        // refuses a later `mprotect(+W)` on it.
        ImageRunKind::Text => base | uapi::KERNITE_RIGHT_EXECUTE as u64,
        // Rodata and the read-only source of a private data run carry no
        // EXECUTE, so a later `mprotect(+X)` is refused. (Bss never aliases —
        // it is pure zero-fill — but the match must be exhaustive.)
        ImageRunKind::RoData | ImageRunKind::Data | ImageRunKind::Bss => base,
    }
}

fn wire_image_kind(kind: ImageRunKind) -> u64 {
    match kind {
        ImageRunKind::Text => STAGE_IMAGE_KIND_TEXT,
        ImageRunKind::RoData => STAGE_IMAGE_KIND_RODATA,
        ImageRunKind::Data => STAGE_IMAGE_KIND_DATA,
        ImageRunKind::Bss => STAGE_IMAGE_KIND_BSS,
    }
}

/// Maps a resolved code MO's runs into the current address space.
struct SelfSink {
    code_mo: CapRef,
}

impl PlacementSink for SelfSink {
    type CodeMo = CapRef;
    type Error = SinkError;

    fn begin_image(
        &mut self,
        code_mo: CapRef,
        envelope: ImageEnvelope,
        _carves: &[Carve],
    ) -> Result<ImageId, SinkError> {
        self.code_mo = code_mo;
        let image_id = unsafe { mm::reserve_image(envelope.base, envelope.bytes) }
            .map_err(|_| SinkError::Reserve)?;
        Ok(ImageId {
            kind: ImageIdKind::MmsrvReservation,
            flags: 0,
            value0: image_id,
            value1: 0,
        })
    }

    fn place_run(&mut self, image: ImageId, run: &Run) -> Result<(), SinkError> {
        let image_id = image.value0;
        let prot = run.prot.0 as u64;
        let image_kind = wire_image_kind(run.kind);
        match run.source {
            RunSource::ZeroFill => {
                unsafe { mm::map_image_run_anon(run.va, run.bytes, prot, image_id, image_kind) }
                    .map_err(|_| SinkError::MapRun)
            }
            RunSource::CleanFromCodeMo { mo_offset_pages } => {
                let alias = dup_for_transfer_with_rights(self.code_mo, alias_rights(run.kind))
                    .ok_or(SinkError::Alias)?;
                unsafe {
                    mm::map_image_run_mo(
                        run.va,
                        run.bytes,
                        prot,
                        false,
                        mo_offset_pages * PAGE,
                        image_id,
                        image_kind,
                        alias,
                    )
                }
                .map_err(|_| SinkError::MapRun)
            }
            RunSource::PrivateFromCodeMo {
                mo_offset_pages,
                file_bytes,
            } => {
                let alias = dup_for_transfer_with_rights(self.code_mo, alias_rights(run.kind))
                    .ok_or(SinkError::Alias)?;
                let needs_rodata_tail_zero =
                    matches!(run.kind, ImageRunKind::RoData) && file_bytes < run.bytes;
                let map_prot = if needs_rodata_tail_zero {
                    prot | (PROT_WRITE as u64)
                } else {
                    prot
                };
                unsafe {
                    mm::map_image_run_mo(
                        run.va,
                        run.bytes,
                        map_prot,
                        true,
                        mo_offset_pages * PAGE,
                        image_id,
                        image_kind,
                        alias,
                    )
                }
                .map_err(|_| SinkError::MapRun)?;
                // The COW child reads the source bytes through `file_bytes`; the
                // run's tail (segment BSS / page padding) must read zero. Writable
                // data runs are already `R-W`; a materialised read-only-data run
                // gets a temporary `+W` map and is dropped back to `R--` below.
                if file_bytes < run.bytes {
                    let tail = run.va + file_bytes;
                    let len = (run.bytes - file_bytes) as usize;
                    // SAFETY: the just-mapped private run covers
                    // `run.va..run.va + run.bytes`; writable data is mapped
                    // `R-W`, and materialised rodata was mapped with temporary
                    // `+W` above specifically for this zero-fill.
                    unsafe { core::ptr::write_bytes(tail as *mut u8, 0, len) };
                }
                if needs_rodata_tail_zero {
                    // SAFETY: this downgrades the same mapped run back to its
                    // final `R--` protection before the image is published to
                    // user code.
                    unsafe { mm::mprotect(run.va as *mut u8, run.bytes, prot as i32) }
                        .map_err(|_| SinkError::MapRun)?;
                }
                Ok(())
            }
        }
    }

    fn abort_image(&mut self, image: ImageId) {
        let _ = unsafe { mm::unmap_image(image.value0) };
    }
}

/// Realize `plan` (from an ELF or PE run-plan producer) into the current address
/// space, mapping every run from `code_mo`. Returns the mmsrv image reservation
/// id — the `dlclose` teardown handle (`MM_UNMAP_IMAGE`).
///
/// # Safety
/// `code_mo` names a `READ|EXECUTE|GRANT|TRANSFER` code MemoryObject the caller
/// owns; the plan's runs lie within its envelope.
pub unsafe fn place_image(code_mo: CapRef, plan: &RunPlan<'_>) -> Result<u64, SinkError> {
    let mut sink = SelfSink { code_mo };
    let id = map_image(&mut sink, code_mo, plan)?;
    Ok(id.value0)
}
