// SPDX-License-Identifier: GPL-2.0-only
//! Backend-agnostic image placement core.
//!
//! A loadable image (ELF or PE) is reduced to a [`RunPlan`]: an envelope of
//! reserved virtual address space plus a list of [`Run`]s, each describing a
//! page-aligned range, its final protection, and where its bytes come from. A
//! [`PlacementSink`] then realizes each run against a concrete backend (mapping
//! into a child address space directly, or driving a memory-manager server over
//! IPC). [`map_image`] is the shared orchestration that walks the plan.
//!
//! The `code_mo` handed to [`map_image`] is **already an execute-bearing**
//! reference to the image's shared code object; conferring EXECUTE happens
//! upstream (the code-loading authority for a code object, or the bootstrap
//! loader for a boot object). A sink only ever *attenuates* per run:
//!
//! * [`ImageRunKind::Text`] keeps `R-X` (mapped from the execute-bearing cap),
//! * [`ImageRunKind::RoData`] is mapped from a no-execute source; if a boundary
//!   page must be materialised to zero a tail, the sink may use a temporary
//!   writable private child but must publish the final region as `R--` so later
//!   `mprotect(+X|+W)` is refused by the image-region ceiling,
//! * [`ImageRunKind::Data`] is a private copy-on-write child mapped `R-W`,
//! * [`ImageRunKind::Bss`] is private zero-fill `R-W`.
//!
//! The plan is produced by format-specific code (`elf`, `pe`) and is a pure
//! function of the parsed headers + the code object, so this module stays free
//! of any backend, server, or capability type.

/// POSIX protection bits, matching the values the kernel map surfaces expect.
pub const PROT_READ: u8 = 0x1;
pub const PROT_WRITE: u8 = 0x2;
pub const PROT_EXEC: u8 = 0x4;

/// A POSIX protection mask (`PROT_READ | PROT_WRITE | PROT_EXEC`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Prot(pub u8);

impl Prot {
    pub const RX: Prot = Prot(PROT_READ | PROT_EXEC);
    pub const RO: Prot = Prot(PROT_READ);
    pub const RW: Prot = Prot(PROT_READ | PROT_WRITE);

    #[inline]
    pub const fn contains(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

/// What a run contributes to the image, independent of where its bytes live.
/// Drives the sink's attenuation choice (which alias / private copy to map).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ImageRunKind {
    /// Executable code — shared `R-X` from the execute-bearing code object.
    Text,
    /// Read-only data — shared `R--` from a no-execute alias of the code object.
    RoData,
    /// Writable initialized data — a private copy-on-write child, `R-W`.
    Data,
    /// Zero-initialized data (`.bss`) — private zero-fill, `R-W`.
    Bss,
}

/// Where a run's bytes come from, in terms of the shared code object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunSource {
    /// Map the code object's pages directly (zero-copy). Valid only when the
    /// run's file offset is page-congruent with its virtual address, so the
    /// object's page offsets line up with the mapping.
    CleanFromCodeMo {
        /// First code-object page backing this run.
        mo_offset_pages: u64,
    },
    /// Clone the code object's pages into a private child, zero the tail beyond
    /// `file_bytes`, and map the child. Used for writable data and for any run
    /// that is not page-congruent (so it cannot be shared zero-copy).
    PrivateFromCodeMo {
        /// First code-object page cloned for this run.
        mo_offset_pages: u64,
        /// Bytes copied from the object; the remainder of the run is zeroed.
        file_bytes: u64,
    },
    /// No backing object — pure zero-fill (`.bss`).
    ZeroFill,
}

/// One page-aligned span of the image with a uniform protection and source.
#[derive(Clone, Copy, Debug)]
pub struct Run {
    /// Run start, an absolute virtual address (page-aligned).
    pub va: u64,
    /// Run length in bytes (a multiple of the page size).
    pub bytes: u64,
    /// Final protection for the run.
    pub prot: Prot,
    /// What the run contributes (selects the sink's attenuation).
    pub kind: ImageRunKind,
    /// Where the run's bytes come from.
    pub source: RunSource,
}

impl Run {
    /// A placeholder used to initialize fixed-size plan buffers before the
    /// producer fills the live entries.
    pub const EMPTY: Run = Run {
        va: 0,
        bytes: 0,
        prot: Prot(0),
        kind: ImageRunKind::Bss,
        source: RunSource::ZeroFill,
    };
}

/// The reserved virtual-address envelope of an image. Inter-segment holes stay
/// reserved so nothing else lands inside the image's span.
#[derive(Clone, Copy, Debug)]
pub struct ImageEnvelope {
    /// Envelope start (page-aligned, absolute).
    pub base: u64,
    /// Envelope length in bytes (page-aligned).
    pub bytes: u64,
    /// The load bias applied to the image's link-time addresses.
    pub load_base: u64,
    /// The image entry point, an absolute virtual address.
    pub entry_pc: u64,
}

/// Discriminates how an [`ImageId`]'s opaque words should be read back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum ImageIdKind {
    /// No teardown handle (e.g. a permanently-pinned boot image).
    None = 0,
    /// A memory-manager reservation id; `value0` is its packed form.
    MmsrvReservation = 1,
    /// A directly-mapped envelope; `value0`/`value1` are its base/bytes.
    DirectEnvelope = 2,
}

/// A backend-opaque handle to a placed image, used for later teardown. The
/// meaning of the words is the placing sink's; only it interprets them.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ImageId {
    pub kind: ImageIdKind,
    pub flags: u32,
    pub value0: u64,
    pub value1: u64,
}

impl ImageId {
    pub const NONE: ImageId = ImageId {
        kind: ImageIdKind::None,
        flags: 0,
        value0: 0,
        value1: 0,
    };
}

/// A region that must be writable after the image is otherwise mapped — the
/// post-map fixups a PE image applies (import address tables, delay-import
/// tables and module handles, the TLS index slot). Expressed as a code-object
/// RVA range so the producer can split it out of an otherwise-shared run. ELF
/// images carry none.
#[derive(Clone, Copy, Debug)]
pub struct Carve {
    pub rva: u64,
    pub bytes: u64,
}

/// A produced placement plan: the reserved envelope plus the runs that fill it.
pub struct RunPlan<'a> {
    pub envelope: ImageEnvelope,
    pub runs: &'a [Run],
    /// PE post-map writable regions (empty for ELF).
    pub carves: &'a [Carve],
}

/// Realizes a [`RunPlan`] against a concrete backend.
///
/// Implementations own (or reference) the execute-bearing `code_mo` and know how
/// to attenuate it per [`Run::kind`] for their backend — mapping directly into a
/// child address space, or driving a memory-manager server over IPC. A sink must
/// never *confer* EXECUTE (the `code_mo` already carries it); it only narrows.
pub trait PlacementSink {
    /// The sink's reference to the shared code object (a capability, a server
    /// handle, …).
    type CodeMo: Copy;
    /// The sink's error type.
    type Error;

    /// Reserve the envelope and record the image. `carves` are the PE post-map
    /// writable regions (empty for ELF). Returns the teardown handle.
    fn begin_image(
        &mut self,
        code_mo: Self::CodeMo,
        envelope: ImageEnvelope,
        carves: &[Carve],
    ) -> Result<ImageId, Self::Error>;

    /// Place one run into the image started by `begin_image`.
    fn place_run(&mut self, image: ImageId, run: &Run) -> Result<(), Self::Error>;

    /// Finalize the image after every run is placed.
    fn finish_image(&mut self, image: ImageId) -> Result<(), Self::Error> {
        let _ = image;
        Ok(())
    }

    /// Tear down a partially-placed image after an error.
    fn abort_image(&mut self, image: ImageId) {
        let _ = image;
    }
}

/// Walk a [`RunPlan`], placing each run through `sink`. On any error the
/// partially-placed image is aborted and the error returned.
pub fn map_image<S: PlacementSink>(
    sink: &mut S,
    code_mo: S::CodeMo,
    plan: &RunPlan<'_>,
) -> Result<ImageId, S::Error> {
    let id = sink.begin_image(code_mo, plan.envelope, plan.carves)?;
    for run in plan.runs {
        if let Err(e) = sink.place_run(id, run) {
            sink.abort_image(id);
            return Err(e);
        }
    }
    if let Err(e) = sink.finish_image(id) {
        sink.abort_image(id);
        return Err(e);
    }
    Ok(id)
}
