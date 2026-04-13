// SPDX-License-Identifier: GPL-2.0-only
//! Win32 path utilities — minimal stub.
//!
//! Win32 path translation (drive letters, backslashes, reserved names,
//! case-insensitive lookup) is performed server-side by `namei_win32`
//! in the VFS. Client-side Win32 APIs (CreateFileA, etc.) pass paths
//! as-is to the VFS via IPC — no client-side translation is needed.
