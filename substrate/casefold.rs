// SPDX-License-Identifier: GPL-2.0-only
//! Unicode 15.1 Simple Case-Folding utilities.
//!
//! Provides codepoint-level folding, UTF-8 string folding, and
//! case-insensitive comparison. The fold table lives in
//! `casefold_table::CASEFOLD_TABLE` (generated from CaseFolding-15.1.txt).
//!
//! These functions are placed in the trona substrate so that every
//! filesystem and VFS layer can share the same folding logic without
//! duplicating the 1457-entry table.

use crate::casefold_table::CASEFOLD_TABLE;

/// Maximum folded buffer size. Large enough for any legal VFS filename
/// after Simple Case-Folding (which is 1:1 at the codepoint level).
pub const FOLD_BUF_MAX: usize = 256;

/// Fold a single Unicode codepoint using Simple Case-Folding.
///
/// ASCII fast path returns `cp + 32` for `A..Z`; everything else goes
/// through a binary search over `CASEFOLD_TABLE`. Unmapped codepoints
/// are returned unchanged.
#[inline]
pub fn fold_codepoint(cp: u32) -> u32 {
    if cp < 0x80 {
        if cp >= b'A' as u32 && cp <= b'Z' as u32 {
            return cp + 32;
        }
        return cp;
    }
    let table = CASEFOLD_TABLE;
    let mut lo = 0usize;
    let mut hi = table.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (k, v) = table[mid];
        if k == cp {
            return v;
        } else if k < cp {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    cp
}

/// Decode UTF-8, fold each codepoint via Simple Case-Folding, re-encode
/// UTF-8 into `dst`. Returns the number of bytes written, or `None` on
/// invalid UTF-8 or if the output would not fit.
pub fn fold_utf8(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    let s = core::str::from_utf8(src).ok()?;
    let mut pos = 0usize;
    for c in s.chars() {
        let folded_cp = fold_codepoint(c as u32);
        let folded_char = char::from_u32(folded_cp)?;
        let mut buf = [0u8; 4];
        let enc_len = folded_char.encode_utf8(&mut buf).len();
        if pos + enc_len > dst.len() {
            return None;
        }
        let dst_slice = &mut dst[pos..pos + enc_len];
        dst_slice.copy_from_slice(&buf[..enc_len]);
        pos += enc_len;
    }
    Some(pos)
}

/// Case-insensitive equality over UTF-8 byte slices. Folds both sides
/// into stack buffers; invalid UTF-8 on either side falls back to raw
/// byte compare.
pub fn casefold_equal(a: &[u8], b: &[u8]) -> bool {
    let mut ba = [0u8; FOLD_BUF_MAX];
    let mut bb = [0u8; FOLD_BUF_MAX];
    match (fold_utf8(a, &mut ba), fold_utf8(b, &mut bb)) {
        (Some(la), Some(lb)) => {
            if la != lb {
                return false;
            }
            ba[..la] == bb[..lb]
        }
        _ => a == b,
    }
}
