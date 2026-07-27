//! SPDX-License-Identifier: GPL-2.0-only
//! ELF RTLD entry and loading logic
//!
//! Module split:
//! - [`main`]   — startup linker (auxv parse, preloaded objects, TLS setup,
//!                handoff). Owns the boot-time path only.
//! - [`object`] — LinkMap helpers (apply_dyn_info, relocate_object,
//!                install_got_entries, _dl_fixup, find_loaded_object) and
//!                runtime DSO loader (`load_object`).
//! - [`scope`]  — symbol scope semantics (RTLD_GLOBAL/LOCAL/NEXT/DEFAULT).
//! - [`tls`]    — runtime TLS module registration, DTV layout, tls_addr /
//!                tls_destroy implementations.
//! - [`dlfcn`]  — `RtldDlfcnV1` function table and dlopen / dlclose / dlsym /
//!                dladdr / dl_iterate_phdr public-facing implementations.

pub mod dlfcn;
pub mod main;
pub mod object;
pub mod scope;
pub mod tls;
