# trona-uapi

`trona-uapi` defines the stable kernel/userspace contract:

- syscall numbers
- error codes
- invoke labels
- object/type constants
- C header-facing low-level ABI types

Current migration status:

1. Canonical Rust constants were moved to `rust/consts.rs`.
2. `trona-lib` now forwards to that file via `include!`.
3. userland call sites and naming cleanup are deferred.
