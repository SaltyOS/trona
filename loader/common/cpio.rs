//! SPDX-License-Identifier: GPL-2.0-only
//! CPIO newc archive parser

const CPIO_MAGIC: &[u8; 6] = b"070701";
const CPIO_HEADER_SIZE: usize = 110;

#[derive(Clone, Copy)]
pub struct CpioEntry {
    pub name: *const u8,
    pub name_len: usize,
    pub data: *const u8,
    pub data_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpioEntryExt {
    pub name: *const u8,
    pub name_len: usize,
    pub data: *const u8,
    pub data_len: usize,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub ino: u32,
}

/// # Safety
/// `archive` must point to `len` bytes of a valid CPIO newc archive.
pub unsafe fn cpio_find_file(archive: *const u8, len: usize, path: &[u8]) -> Option<CpioEntry> {
    let mut iter = unsafe { CpioIter::new(archive, len) };
    while let Some(entry) = iter.next_entry() {
        if entry.name_len == path.len() {
            let name_slice = unsafe { core::slice::from_raw_parts(entry.name, entry.name_len) };
            if name_slice == path {
                return Some(entry);
            }
        }
    }
    None
}

/// # Safety
/// `archive` must point to `len` bytes of a valid CPIO newc archive.
pub unsafe fn cpio_find_file_ext(
    archive: *const u8,
    len: usize,
    path: &[u8],
) -> Option<CpioEntryExt> {
    let mut iter = unsafe { CpioIter::new(archive, len) };
    while let Some(entry) = iter.next_entry_ext() {
        if entry.name_len == path.len() {
            let name_slice = unsafe { core::slice::from_raw_parts(entry.name, entry.name_len) };
            if name_slice == path {
                return Some(entry);
            }
        }
    }
    None
}

/// # Safety
/// `archive` must point to `len` bytes of a valid CPIO newc archive.
pub unsafe fn cpio_archive_size(archive: *const u8, len: usize) -> usize {
    let mut iter = unsafe { CpioIter::new(archive, len) };
    while iter.next_entry().is_some() {}
    iter.offset
}

pub struct CpioIter {
    base: *const u8,
    len: usize,
    offset: usize,
}

impl CpioIter {
    /// # Safety
    /// `base` must point to at least `len` readable bytes.
    pub unsafe fn new(base: *const u8, len: usize) -> Self {
        Self {
            base,
            len,
            offset: 0,
        }
    }

    pub fn next_entry(&mut self) -> Option<CpioEntry> {
        let (name_ptr, name_len, data_ptr, data_len, _hdr) = self.advance()?;
        Some(CpioEntry {
            name: name_ptr,
            name_len,
            data: data_ptr,
            data_len,
        })
    }

    pub fn next_entry_ext(&mut self) -> Option<CpioEntryExt> {
        let (name_ptr, name_len, data_ptr, data_len, hdr) = self.advance()?;
        Some(CpioEntryExt {
            name: name_ptr,
            name_len,
            data: data_ptr,
            data_len,
            ino: parse_hex8(unsafe { hdr.add(6) }),
            mode: parse_hex8(unsafe { hdr.add(14) }),
            uid: parse_hex8(unsafe { hdr.add(22) }),
            gid: parse_hex8(unsafe { hdr.add(30) }),
            nlink: parse_hex8(unsafe { hdr.add(38) }),
            mtime: parse_hex8(unsafe { hdr.add(46) }),
        })
    }

    fn advance(&mut self) -> Option<(*const u8, usize, *const u8, usize, *const u8)> {
        if self.offset + CPIO_HEADER_SIZE > self.len {
            return None;
        }

        let hdr = unsafe { self.base.add(self.offset) };
        let magic = unsafe { core::slice::from_raw_parts(hdr, 6) };
        if magic != CPIO_MAGIC {
            return None;
        }

        let namesize = parse_hex8(unsafe { hdr.add(94) }) as usize;
        let filesize = parse_hex8(unsafe { hdr.add(54) }) as usize;

        let name_start = self.offset + CPIO_HEADER_SIZE;
        let name_end = align4(name_start + namesize);
        let data_start = name_end;
        let data_end = align4(data_start + filesize);

        if data_end > self.len {
            return None;
        }

        let actual_name_len = if namesize > 0 { namesize - 1 } else { 0 };
        let name_ptr = unsafe { self.base.add(name_start) };

        if actual_name_len == 10 {
            let name_slice = unsafe { core::slice::from_raw_parts(name_ptr, 10) };
            if name_slice == b"TRAILER!!!" {
                self.offset = data_end;
                return None;
            }
        }

        self.offset = data_end;
        Some((
            name_ptr,
            actual_name_len,
            unsafe { self.base.add(data_start) },
            filesize,
            hdr,
        ))
    }
}

fn parse_hex8(ptr: *const u8) -> u32 {
    let mut val = 0u32;
    for i in 0..8 {
        let c = unsafe { *ptr.add(i) };
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        };
        val = (val << 4) | digit as u32;
    }
    val
}

#[inline]
const fn align4(v: usize) -> usize {
    (v + 3) & !3
}
