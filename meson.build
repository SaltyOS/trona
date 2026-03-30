# libtrona.so - SaltyOS System Call Library (Rust, 3-crate build)
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds three Rust crates → libtrona.so:
#   1. trona (substrate) — syscall, IPC, invoke, types, consts
#   2. trona_posix       — POSIX wrappers over substrate IPC
#   3. trona_loader      — ELF loading, CPIO parsing, dynamic linking
# Plus fork.S assembly and the ld-trona.so dynamic linker (rtld/).

libtrona_link = meson.current_source_dir() / 'arch' / arch / 'libtrona.ld'
libtrona_build_dir = meson.current_build_dir()
rust_build_dir = meson.project_build_root() / 'rust'

# Common rustc flags for userland (PIC, small code model)
rust_userland_args = [
  '--edition=2024',
  '--target=' + rust_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=small',
  '-C', 'relocation-model=pic',
  '--sysroot=/dev/null',
  '--extern', 'core=' + rust_build_dir / 'libcore.rmeta',
  '--extern', 'compiler_builtins=' + rust_build_dir / 'libcompiler_builtins.rmeta',
  '-L', rust_build_dir,
  '-L', libtrona_build_dir,
]
if get_option('debug_symbols')
  rust_userland_args += ['-C', 'debuginfo=2']
endif

# SSE2-accelerated basaltc routines — auto-enabled on x86_64 (ISA baseline).
if arch == 'x86_64'
  rust_userland_args += ['--cfg=basaltc_sse2',
    '-C', 'target-feature=+sse,+sse2']
endif

# NEON/FPU — auto-enabled on aarch64 (NEON is mandatory in ARMv8-A).
if arch == 'aarch64'
  rust_userland_args += ['--cfg=basaltc_neon']
endif

# Compile-time log-level cfg flags for userland.
# These enable the uinfo!/udebug!/uwarn! macros in serial.rs at zero runtime cost when off.
ulog_level = get_option('userland_log_level')
if ulog_level == 'trace'
  rust_userland_args += ['--cfg', 'ulog_trace', '--cfg', 'ulog_debug', '--cfg', 'ulog_info', '--cfg', 'ulog_warn']
elif ulog_level == 'debug'
  rust_userland_args += ['--cfg', 'ulog_debug', '--cfg', 'ulog_info', '--cfg', 'ulog_warn']
elif ulog_level == 'info'
  rust_userland_args += ['--cfg', 'ulog_info', '--cfg', 'ulog_warn']
elif ulog_level == 'warn'
  rust_userland_args += ['--cfg', 'ulog_warn']
# else: 'error' — no cfgs, all gated output compiled out
endif

# Per-program debug override list. Programs in this list get ulog_debug
# enabled even when the global userland_log_level is below 'debug'.
userland_debug_list = get_option('userland_debug_programs').split(',')

# fork.S compile-time feature flags
fork_asm_args = []
if arch == 'x86_64'
  fork_asm_args += ['-DSALTY_X86_SIMD=1']
endif

# =============================================================================
# Crate 1: trona (substrate) — syscall, IPC, invoke, types, consts
# =============================================================================

trona_substrate = custom_target('trona_substrate',
  input: files('substrate/lib.rs'),
  output: ['libtrona.o', 'libtrona.rmeta'],
  depfile: 'libtrona.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=trona',
    '--crate-type=lib',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins],
  build_by_default: true,
)

trona_substrate_obj = trona_substrate[0]

# Path strings for --extern in downstream crates
trona_rmeta = libtrona_build_dir / 'libtrona.rmeta'

# =============================================================================
# Crate 2: trona_posix — POSIX wrappers (depends on trona substrate)
# =============================================================================

trona_posix = custom_target('trona_posix',
  input: files('posix/lib.rs'),
  output: ['libtrona_posix.o', 'libtrona_posix.rmeta'],
  depfile: 'libtrona_posix.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=trona_posix',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_substrate],
  build_by_default: true,
)

trona_posix_obj = trona_posix[0]
trona_posix_rmeta = libtrona_build_dir / 'libtrona_posix.rmeta'

# =============================================================================
# Crate 3: trona_loader — ELF/CPIO/dynamic loading (depends on trona + trona_posix)
# =============================================================================

trona_loader = custom_target('trona_loader',
  input: files('loader/lib.rs'),
  output: ['libtrona_loader.o', 'libtrona_loader.rmeta'],
  depfile: 'libtrona_loader.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=trona_loader',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_substrate, trona_posix],
  build_by_default: true,
)

trona_loader_obj = trona_loader[0]
trona_loader_rmeta = libtrona_build_dir / 'libtrona_loader.rmeta'

# =============================================================================
# fork.S — arch-specific fork assembly
# =============================================================================

fork_obj = custom_target('fork_asm',
  input: files('posix/arch' / arch / 'fork.S'),
  output: 'fork.o',
  command: [cc_cmd, '--target=' + c_target, fork_asm_args, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# =============================================================================
# Link: all .o files → libtrona.so
# =============================================================================

libtrona_so = custom_target('libtrona_so',
  input: [trona_substrate_obj, trona_posix_obj, trona_loader_obj,
          fork_obj, core_obj, compiler_builtins_obj],
  output: 'libtrona.so',
  command: [cc_cmd,
    '--target=' + c_target,
    '-shared',
    '-nostdlib', '-nostartfiles',
    '-fno-stack-protector',
    '-Wl,-soname,libtrona.so',
    '-T', libtrona_link,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)

# =============================================================================
# Runtime dynamic linker (ld-trona.so)
# =============================================================================

subdir('rtld')

# =============================================================================
# uapi headers (shared userspace/kernel contract)
# =============================================================================

subdir('uapi')

# =============================================================================
# Exported variables for downstream consumers (userland, top-level meson.build)
# =============================================================================
#
# Build directory / path strings:
#   libtrona_build_dir  — build directory path (for -L flags)
#   trona_rmeta         — path string for --extern trona=...
#   trona_posix_rmeta   — path string for --extern trona_posix=...
#
# Custom targets (for depends/input):
#   libtrona_so         — libtrona.so shared library
#   libtrona_rust       — trona substrate target (use for depends in userland)
#   ld_trona_so         — ld-trona.so dynamic linker (from rtld/)
#   fork_obj            — fork assembly object (for init static link)
#
# Individual .o files (for init static link):
#   trona_substrate_obj — trona substrate .o
#   trona_posix_obj     — trona_posix .o
#   trona_loader_obj    — trona_loader .o

libtrona_rust = trona_substrate
