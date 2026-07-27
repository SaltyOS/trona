// SPDX-License-Identifier: GPL-2.0-only
//! ELF → [`RunPlan`] producer.
//!
//! Pure over the parsed program headers, the load bias, and the entry point: it
//! classifies each page of the image's load span into a [`Run`] whose source is
//! expressed against the shared code object (the ELF file mapped as a
//! MemoryObject), so a backend [`crate::image::PlacementSink`] can realize it
//! without re-reading the file. No backend, server, or capability type appears
//! here.

use super::header::load_span;
use super::types::{Elf64Phdr, PAGE_SIZE, PF_W, PF_X, PT_LOAD};
use crate::common::image::{
    ImageEnvelope, ImageRunKind, PROT_EXEC, PROT_READ, PROT_WRITE, Prot, Run, RunSource,
};

const PAGE: u64 = PAGE_SIZE as u64;

/// Why an ELF image cannot be reduced to a shareable run plan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlanError {
    /// A `PT_LOAD`'s file offset differs from its virtual address (or its file
    /// size exceeds its memory size), so its pages do not line up with the code
    /// object's pages. The runtime targets are `ET_DYN` PIEs, which always have
    /// `p_offset == p_vaddr`.
    SkewedSegment,
    /// One page is covered by both a writable and an executable segment — a
    /// single page has one protection and `W^X` forbids `R-W-X`.
    WriteExecPage,
    /// An executable page is not cleanly shareable, so realizing it would need a
    /// private executable copy; conferring EXECUTE on a fresh copy is an
    /// authority the placement layer does not hold. Well-formed PIEs never
    /// produce this.
    PrivateExec,
    /// The caller's run buffer was too small for the produced plan.
    TooManyRuns,
    /// Address arithmetic overflowed.
    Overflow,
}

/// Per-page classification of an image page.
struct PageClass {
    /// Union protection (POSIX bits) of the segments covering the page.
    prot: u8,
    /// Highest file-backed virtual address within the page (`page_va` if none).
    file_end_va: u64,
    /// The page is non-writable and completely file-backed by load segments.
    clean: bool,
}

fn loaded_bytes_are_file_backed(
    phdrs: &[Elf64Phdr],
    load_base: u64,
    page_va: u64,
    page_end: u64,
) -> Result<bool, PlanError> {
    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let seg_start = load_base
            .checked_add(ph.p_vaddr)
            .ok_or(PlanError::Overflow)?;
        let seg_mem_end = seg_start
            .checked_add(ph.p_memsz)
            .ok_or(PlanError::Overflow)?;
        if seg_mem_end <= page_va || seg_start >= page_end {
            continue;
        }
        let seg_file_end = seg_start
            .checked_add(ph.p_filesz)
            .ok_or(PlanError::Overflow)?;
        let covered_end = core::cmp::min(page_end, seg_mem_end);
        if covered_end > seg_file_end {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Classify one page. `None` means no `PT_LOAD` covers it (a reserved hole).
fn classify_page(
    phdrs: &[Elf64Phdr],
    load_base: u64,
    page_va: u64,
) -> Result<Option<PageClass>, PlanError> {
    let page_end = page_va.checked_add(PAGE).ok_or(PlanError::Overflow)?;
    let mut count = 0u32;
    let mut wants_exec = false;
    let mut wants_write = false;
    let mut file_end_va = page_va;
    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let seg_start = load_base
            .checked_add(ph.p_vaddr)
            .ok_or(PlanError::Overflow)?;
        let seg_mem_end = seg_start
            .checked_add(ph.p_memsz)
            .ok_or(PlanError::Overflow)?;
        if seg_mem_end <= page_va || seg_start >= page_end {
            continue;
        }
        count += 1;
        wants_exec |= ph.p_flags & PF_X != 0;
        wants_write |= ph.p_flags & PF_W != 0;
        let seg_file_end = seg_start
            .checked_add(ph.p_filesz)
            .ok_or(PlanError::Overflow)?;
        let clamped = core::cmp::min(page_end, seg_file_end);
        if clamped > file_end_va {
            file_end_va = clamped;
        }
    }
    if count == 0 {
        return Ok(None);
    }
    if wants_exec && wants_write {
        return Err(PlanError::WriteExecPage);
    }
    let mut prot = PROT_READ;
    if wants_exec {
        prot |= PROT_EXEC;
    }
    if wants_write {
        prot |= PROT_WRITE;
    }
    let clean = !wants_write && loaded_bytes_are_file_backed(phdrs, load_base, page_va, page_end)?;
    Ok(Some(PageClass {
        prot,
        file_end_va,
        clean,
    }))
}

/// A maximal run of consecutive pages with the same protection and share class.
struct PendingRun {
    start_va: u64,
    pages: u64,
    prot: u8,
    clean: bool,
    file_end_va: u64,
}

impl PendingRun {
    fn end_va(&self) -> u64 {
        self.start_va + self.pages * PAGE
    }

    fn can_extend(&self, info: &PageClass, page_va: u64) -> bool {
        if page_va != self.end_va() || self.prot != info.prot || self.clean != info.clean {
            return false;
        }
        // A private run clones one contiguous file extent and zero-fills the
        // tail within its last page, so:
        //   - a page with no file content (pure BSS) must start its own
        //     ZeroFill run: cloning `run.bytes` worth would extend past the
        //     source MO's pages and fail `MO_CLONE_RANGE`
        //     (mmsrv/src/mmap.rs:885; kernite/src/syscall/mo.rs:489). The
        //     resulting `RunSource::ZeroFill` run is mapped via
        //     `mm::map_image_run_anon` inside the same image reservation.
        //   - once the run has opened a zero gap (boundary page at the end
        //     where `p_memsz > p_filesz` mid-page), it must not fold in a
        //     later file-backed page — the source MO has no contiguous
        //     extent covering it.
        if !self.clean {
            if info.file_end_va <= page_va {
                return false;
            }
            if self.file_end_va < self.end_va() {
                return false;
            }
        }
        true
    }

    fn extend(&mut self, info: &PageClass) {
        let page_start = self.end_va();
        self.pages += 1;
        if info.file_end_va > page_start && info.file_end_va > self.file_end_va {
            self.file_end_va = info.file_end_va;
        }
    }

    /// Convert a finished run into a [`Run`].
    fn finish(&self, load_base: u64) -> Result<Run, PlanError> {
        let bytes = self.pages.checked_mul(PAGE).ok_or(PlanError::Overflow)?;
        // p_offset == p_vaddr (enforced in `plan_elf`), so the run's code-object
        // page offset is exactly its page offset from the load base.
        let mo_offset_pages = self
            .start_va
            .checked_sub(load_base)
            .ok_or(PlanError::Overflow)?
            / PAGE;
        let (source, kind) = if self.clean {
            let kind = if self.prot & PROT_EXEC != 0 {
                ImageRunKind::Text
            } else {
                ImageRunKind::RoData
            };
            (RunSource::CleanFromCodeMo { mo_offset_pages }, kind)
        } else if self.prot & PROT_EXEC != 0 {
            // A non-shareable executable page would need a private R-X copy,
            // which the placement layer cannot confer EXECUTE on.
            return Err(PlanError::PrivateExec);
        } else {
            let file_bytes = self.file_end_va.saturating_sub(self.start_va);
            if file_bytes == 0 {
                let kind = if self.prot & PROT_WRITE != 0 {
                    ImageRunKind::Bss
                } else {
                    ImageRunKind::RoData
                };
                (RunSource::ZeroFill, kind)
            } else {
                let kind = if self.prot & PROT_WRITE != 0 {
                    ImageRunKind::Data
                } else {
                    ImageRunKind::RoData
                };
                (
                    RunSource::PrivateFromCodeMo {
                        mo_offset_pages,
                        file_bytes,
                    },
                    kind,
                )
            }
        };
        Ok(Run {
            va: self.start_va,
            bytes,
            prot: Prot(self.prot),
            kind,
            source,
        })
    }
}

fn emit_run(
    r: &PendingRun,
    load_base: u64,
    out: &mut [Run],
    count: &mut usize,
) -> Result<(), PlanError> {
    if *count >= out.len() {
        return Err(PlanError::TooManyRuns);
    }
    out[*count] = r.finish(load_base)?;
    *count += 1;
    Ok(())
}

/// Produce the [`RunPlan`] runs for an ELF image into `out`.
///
/// `load_base` is the load bias (0 for `ET_EXEC`, the chosen base for `ET_DYN`),
/// `entry` is the ELF header entry point (relative to the bias). Returns the
/// envelope and the number of runs written to `out`. The caller wraps the
/// envelope, `&out[..count]`, and any carves into a `RunPlan`.
pub fn plan_elf(
    phdrs: &[Elf64Phdr],
    load_base: u64,
    entry: u64,
    out: &mut [Run],
) -> Result<(ImageEnvelope, usize), PlanError> {
    // The shareable / private split assumes a page-congruent file layout; the
    // ET_DYN PIE runtime targets all use p_offset == p_vaddr. A skewed layout
    // would mis-place shared pages, so reject it rather than mis-map.
    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        if ph.p_filesz > ph.p_memsz || ph.p_offset != ph.p_vaddr {
            return Err(PlanError::SkewedSegment);
        }
    }

    let entry_pc = load_base.wrapping_add(entry);
    let Some((span_lo, span_hi)) = load_span(phdrs) else {
        return Ok((
            ImageEnvelope {
                base: 0,
                bytes: 0,
                load_base,
                entry_pc,
            },
            0,
        ));
    };
    let span_start = load_base.checked_add(span_lo).ok_or(PlanError::Overflow)?;
    let span_end = load_base.checked_add(span_hi).ok_or(PlanError::Overflow)?;
    let base = span_start & !(PAGE - 1);
    let end = span_end.checked_add(PAGE - 1).ok_or(PlanError::Overflow)? & !(PAGE - 1);

    let mut count = 0usize;
    let mut run: Option<PendingRun> = None;
    let mut page_va = base;
    while page_va < end {
        match classify_page(phdrs, load_base, page_va)? {
            None => {
                if let Some(r) = run.take() {
                    emit_run(&r, load_base, out, &mut count)?;
                }
            }
            Some(info) => {
                let extend = run.as_ref().is_some_and(|r| r.can_extend(&info, page_va));
                if extend {
                    if let Some(r) = run.as_mut() {
                        r.extend(&info);
                    }
                } else {
                    if let Some(r) = run.take() {
                        emit_run(&r, load_base, out, &mut count)?;
                    }
                    run = Some(PendingRun {
                        start_va: page_va,
                        pages: 1,
                        prot: info.prot,
                        clean: info.clean,
                        file_end_va: info.file_end_va,
                    });
                }
            }
        }
        page_va = page_va.checked_add(PAGE).ok_or(PlanError::Overflow)?;
    }
    if let Some(r) = run.take() {
        emit_run(&r, load_base, out, &mut count)?;
    }

    Ok((
        ImageEnvelope {
            base,
            bytes: end - base,
            load_base,
            entry_pc,
        },
        count,
    ))
}
