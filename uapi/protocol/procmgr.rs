// Process manager IPC protocol labels.
// SPDX-License-Identifier: GPL-2.0-only

pub const PM_SPAWN: u64 = 1;
pub const PM_EXIT: u64 = 2;
pub const PM_WAIT: u64 = 3;
pub const PM_GETPID: u64 = 4;
pub const PM_FORK: u64 = 5;
pub const PM_EXEC: u64 = 6;
pub const PM_GETPPID: u64 = 7;
pub const PM_KILL: u64 = 8;
pub const PM_SIGACTION: u64 = 9;
pub const PM_GETUID: u64 = 10;
pub const PM_GETGID: u64 = 11;
pub const PM_SETPGID: u64 = 12;
pub const PM_GETPGID: u64 = 13;
pub const PM_SETSID: u64 = 14;
pub const PM_GETEUID: u64 = 15;
pub const PM_GETEGID: u64 = 16;
pub const PM_GETGROUPS: u64 = 17;
pub const PM_REGISTER: u64 = 21;
pub const PM_GETSID: u64 = 22;
pub const PM_GETPGID_BADGE: u64 = 23;
pub const PM_GETSID_BADGE: u64 = 24;
pub const PM_KILL_PGID: u64 = 25;
pub const PM_INJECT_CAP: u64 = 26;
pub const PM_LIST_PIDS: u64 = 27;
pub const PM_GET_PROC_INFO: u64 = 28;
pub const PM_RESUME: u64 = 29;
pub const PM_UMASK: u64 = 30;
pub const PM_SETITIMER: u64 = 32;
pub const PM_GETITIMER: u64 = 33;
pub const PM_GET_EXE_PATH: u64 = 34;
pub const PM_DUMP_PENDING: u64 = 35;
pub const PM_GET_THREAD_CAPS: u64 = 36;

// Multi-user credential management
pub const PM_SETUID: u64 = 37;
pub const PM_SETGID: u64 = 38;
pub const PM_SETEUID: u64 = 39;
pub const PM_SETEGID: u64 = 40;
pub const PM_SETREUID: u64 = 41;
pub const PM_SETREGID: u64 = 42;
pub const PM_SETGROUPS: u64 = 43;
pub const PM_GET_CREDS_BY_BADGE: u64 = 44;
pub const PM_GETRESUID: u64 = 45;
pub const PM_GETRESGID: u64 = 46;
pub const PM_SETRESUID: u64 = 47;
pub const PM_SETRESGID: u64 = 48;

// Resource limits
pub const PM_GETRLIMIT: u64 = 49;
pub const PM_SETRLIMIT: u64 = 50;
pub const PM_SET_SESSION_TTY: u64 = 51;
pub const PM_CLEAR_SESSION_TTY: u64 = 52;
pub const PM_SET_SESSION_TTY_PGRP: u64 = 53;
pub const PM_REGISTER_PERSONALITY_PROVIDER: u64 = 54;

// Thread lifecycle (procmgr owns process AND thread lifecycle).
// Personality-agnostic — invoked from libpthread / libwin32 thread shims.
pub const PM_THREAD_CREATE: u64 = 55;
pub const PM_THREAD_EXIT: u64 = 56;
pub const PM_THREAD_JOIN: u64 = 57;
pub const PM_THREAD_DETACH: u64 = 58;
pub const PM_THREAD_LIST: u64 = 59;

// Boot-time service registry transfer (option 5).
//
// Init parses every `.service` file in the initrd. Pre-procmgr services it
// spawns directly. Post-procmgr services need their `Require=` entries
// resolved by procmgr at spawn time, so init ships the parsed service defs
// to procmgr in one shot via this label. Payload is a single frame cap in
// `ipc_buffer.caps[0]`; the frame contains a `TronaProcmgrServiceDefsV1`
// header followed by `count` `TronaProcmgrServiceDefV1` entries. Procmgr
// maps the frame, validates magic+version, copies entries into a static
// registry, unmaps, and acks `TRONA_OK`.
pub const PM_REGISTER_SERVICE_DEFS: u64 = 60;

// Pre-procmgr provider registration.
//
// Init calls this label once per pre-procmgr service whose endpoint
// procmgr will need later (when a post-procmgr child has
// `Require=<provider>`). Payload:
//
// - `extra_caps[0]` = the provider's listener EP (init transfers a copy)
// - `regs[0]` = name length
// - `regs[1..]` = packed provider name bytes
//
// Procmgr copies the cap into its own provider-slot range, registers
// `(name, slot)` in `PROVIDER_REGISTRY`, deletes the receive slot, and
// acks `TRONA_OK`. Post-procmgr providers are registered automatically by
// procmgr's spawn path — they do not use this label.
pub const PM_REGISTER_PROVIDER: u64 = 61;
pub const PM_GET_SESSION_TTY_BADGE: u64 = 62;
