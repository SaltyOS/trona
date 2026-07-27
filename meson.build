# libtrona.so - SaltyOS System Call Library (Rust, 6-crate build)
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds six Rust crates → libtrona.so:
#   1. trona_kernel   — thin kernel ABI wrapper (syscall, IPC, invoke, IPC buffer, kernel ABI shapes)
#   2. trona_protocol — cross-server wire constants and reply payload shapes
#   3. trona_server   — server-loop primitives (EQ_WAIT reactor, RecvSlotArena, ReplyLease)
#   4. trona_runtime  — process runtime (slot allocator, lazy lookup, TLS, weak symbols, C-ABI exports)
#   5. trona_posix    — POSIX wrappers over the four crates above
#   6. trona_loader   — ELF loading, CPIO parsing, dynamic linking
# Plus fork.S assembly and the ldtrona-elf.so / ldtrona-pe.so dynamic linkers (loader/).

libtrona_link = meson.current_source_dir() / 'arch' / arch / 'libtrona.ld'
libtrona_build_dir = meson.current_build_dir()
core_src = rust_lib_src / 'core/src/lib.rs'
core_rmeta_path = libtrona_build_dir / 'libcore-trona.rmeta'
compiler_builtins_rmeta_path = libtrona_build_dir / 'libcompiler_builtins-trona.rmeta'
compiler_builtins_rtld_rmeta_path = libtrona_build_dir / 'libcompiler_builtins-rtld.rmeta'

rust_userland_support_args = [
  '--edition=2024',
  '--target=' + rust_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=small',
  '-C', 'relocation-model=pic',
]
if get_option('debug_symbols')
  rust_userland_support_args += ['-C', 'debuginfo=2']
endif

core = custom_target('trona_core',
  input: [],
  output: ['core-trona.o', 'libcore-trona.rmeta'],
  command: [
    rustc,
    rust_userland_support_args,
    '--cfg', 'no_fp_fmt_parse',
    # Disambiguate rustc's intermediate CGU filenames from the kernite and
    # kernel32 `--crate-name=core` builds that otherwise share the same
    # top-level build dir; without this, parallel ninja jobs race on
    # `core.core.<hash>-cgu.*.rcgu.o` temp files.
    '-C', 'extra-filename=-trona',
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=core',
    '--crate-type=lib',
    core_src,
  ],
  build_by_default: true,
)

core_obj = core[0]
core_rmeta = core_rmeta_path

compiler_builtins = custom_target('trona_compiler_builtins',
  input: files('compiler_builtins.rs'),
  output: ['compiler_builtins-trona.o', 'libcompiler_builtins-trona.rmeta'],
  command: [
    rustc,
    rust_userland_support_args,
    # Same intermediate-filename disambiguation rationale as `trona_core` above.
    '-C', 'extra-filename=-trona',
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=compiler_builtins',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + core_rmeta,
    '-L', libtrona_build_dir,
    '@INPUT@',
  ],
  depends: [core],
  build_by_default: true,
)

compiler_builtins_obj = compiler_builtins[0]
compiler_builtins_rmeta = compiler_builtins_rmeta_path

compiler_builtins_rtld = custom_target('trona_compiler_builtins_rtld',
  input: files('compiler_builtins.rs'),
  output: ['compiler_builtins-rtld.o', 'libcompiler_builtins-rtld.rmeta'],
  command: [
    rustc,
    rust_userland_support_args,
    '--cfg', 'trona_mem_builtins',
    # Distinct from `trona_compiler_builtins` above — same crate name compiled
    # with different cfg, so intermediate CGU files must not share a prefix.
    '-C', 'extra-filename=-rtld',
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=compiler_builtins',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + core_rmeta,
    '-L', libtrona_build_dir,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins],
  build_by_default: true,
)

compiler_builtins_rtld_obj = compiler_builtins_rtld[0]
compiler_builtins_rtld_rmeta = compiler_builtins_rtld_rmeta_path

# Common rustc flags for userland (PIC, small code model)
rust_userland_args = [
  '--edition=2024',
  '--target=' + rust_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=small',
  '-C', 'relocation-model=pic',
  # Stack-clash protection: rustc's *-unknown-saltyos targets enable
  # inline stack probes by default (see the target JSON), so every
  # large frame / alloca touches each guard page on the way down. The
  # kernel publishes the per-thread stack reserve via
  # TCB_SET_STACK_BOUNDS and catches guard-page accesses; probes are
  # the mandatory compiler-side complement so a single `alloca(huge)`
  # cannot skip the guard entirely.
  '--sysroot=/dev/null',
  '--extern', 'core=' + core_rmeta,
  '--extern', 'compiler_builtins=' + compiler_builtins_rmeta,
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

if not get_option('userland_aslr')
  rust_userland_args += ['--cfg', 'trona_disable_aslr']
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
# UAPI crate (userland flavor) — bindgen mirror of kernite C headers under
# `kernite/include/uapi/`. Same generated source as the kernel rmeta;
# only the rustc target spec differs.
# =============================================================================

trona_uapi = custom_target('trona_uapi',
  input: uapi_bindgen_rs,
  output: ['libuapi.o', 'libuapi.rmeta'],
  depfile: 'libuapi.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=uapi',
    '-C', 'extra-filename=-uapi',
    '--crate-type=lib',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, uapi_bindgen],
  build_by_default: true,
)

trona_uapi_obj = trona_uapi[0]
trona_uapi_rmeta = libtrona_build_dir / 'libuapi.rmeta'

# =============================================================================
# Crate 1: trona_kernel — thin kernel ABI wrapper
# =============================================================================

trona_kernel = custom_target('trona_kernel',
  input: files('kernel/src/lib.rs'),
  output: ['libtrona_kernel.o', 'libtrona_kernel.rmeta'],
  depfile: 'libtrona_kernel.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=trona_kernel',
    '--crate-type=lib',
    '--extern', 'uapi=' + trona_uapi_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_uapi],
  build_by_default: true,
)
trona_kernel_obj = trona_kernel[0]
trona_kernel_rmeta = libtrona_build_dir / 'libtrona_kernel.rmeta'

trona_kernel_syscall_obj = custom_target('trona_kernel_syscall_asm',
  input: files('kernel/src/arch' / arch / 'syscall.S'),
  output: 'trona_kernel_syscall.o',
  command: [cc_cmd, '--target=' + c_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# =============================================================================
# Crate 2: trona_protocol — cross-server wire constants + reply payload shapes
# =============================================================================

trona_protocol = custom_target('trona_protocol',
  input: files('protocol/src/lib.rs'),
  output: ['libtrona_protocol.o', 'libtrona_protocol.rmeta'],
  depfile: 'libtrona_protocol.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=trona_protocol',
    '--crate-type=lib',
    '--extern', 'uapi=' + trona_uapi_rmeta,
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_uapi, trona_kernel],
  build_by_default: true,
)
trona_protocol_obj = trona_protocol[0]
trona_protocol_rmeta = libtrona_build_dir / 'libtrona_protocol.rmeta'

# =============================================================================
# Crate 3: trona_server — server-loop primitives (EQ_WAIT reactor, RecvSlotArena, ReplyLease)
# =============================================================================

trona_server = custom_target('trona_server',
  input: files('server/src/lib.rs'),
  output: ['libtrona_server.o', 'libtrona_server.rmeta'],
  depfile: 'libtrona_server.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=trona_server',
    '--crate-type=lib',
    '--extern', 'uapi=' + trona_uapi_rmeta,
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_uapi, trona_kernel],
  build_by_default: true,
)
trona_server_obj = trona_server[0]
trona_server_rmeta = libtrona_build_dir / 'libtrona_server.rmeta'

# =============================================================================
# Crate 4: trona_runtime — process runtime (slot alloc, lazy lookup, TLS, C-ABI exports)
# =============================================================================

trona_runtime = custom_target('trona_runtime',
  input: files('runtime/src/lib.rs'),
  output: ['libtrona_runtime.o', 'libtrona_runtime.rmeta'],
  depfile: 'libtrona_runtime.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=trona_runtime',
    '--crate-type=lib',
    '--extern', 'uapi=' + trona_uapi_rmeta,
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '--extern', 'trona_protocol=' + trona_protocol_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_uapi, trona_kernel, trona_protocol],
  build_by_default: true,
)
trona_runtime_obj = trona_runtime[0]
trona_runtime_rmeta = libtrona_build_dir / 'libtrona_runtime.rmeta'

trona_runtime_tls_obj = custom_target('trona_runtime_tls_asm',
  input: files('runtime/src/thread/arch' / arch / 'tls.S'),
  output: 'trona_runtime_tls.o',
  command: [cc_cmd, '--target=' + c_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

trona_runtime_thread_obj = custom_target('trona_runtime_thread_asm',
  input: files('runtime/src/thread/arch' / arch / 'thread.S'),
  output: 'trona_runtime_thread.o',
  command: [cc_cmd, '--target=' + c_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# =============================================================================
# Crate 5: trona_posix — POSIX wrappers
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
    '--extern', 'uapi=' + trona_uapi_rmeta,
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '--extern', 'trona_protocol=' + trona_protocol_rmeta,
    '--extern', 'trona_server=' + trona_server_rmeta,
    '--extern', 'trona_runtime=' + trona_runtime_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_uapi, trona_kernel, trona_protocol, trona_server, trona_runtime],
  build_by_default: true,
)

trona_posix_obj = trona_posix[0]
trona_posix_rmeta = libtrona_build_dir / 'libtrona_posix.rmeta'

trona_pthread_obj = custom_target('trona_pthread_asm',
  input: files('posix/arch' / arch / 'pthread.S'),
  output: 'pthread.o',
  command: [cc_cmd, '--target=' + c_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# =============================================================================
# Crate 6: trona_loader — ELF/CPIO/dynamic loading
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
    '--extern', 'uapi=' + trona_uapi_rmeta,
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '--extern', 'trona_protocol=' + trona_protocol_rmeta,
    '--extern', 'trona_server=' + trona_server_rmeta,
    '--extern', 'trona_runtime=' + trona_runtime_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_uapi, trona_kernel, trona_protocol, trona_server, trona_runtime],
  build_by_default: true,
)

trona_loader_obj = trona_loader[0]
trona_loader_rmeta = libtrona_build_dir / 'libtrona_loader.rmeta'

# =============================================================================
# kernel32.dll — Win32 API compatibility layer for PE programs (real PE/COFF)
# =============================================================================

if arch == 'x86_64'
  kernel32_rust_target = 'x86_64-pc-windows-gnu'
  kernel32_asm_target = 'x86_64-pc-windows-gnu'
  kernel32_pe_machine = 'amd64'
elif arch == 'aarch64'
  kernel32_rust_target = 'aarch64-pc-windows-gnullvm'
  kernel32_asm_target = 'aarch64-windows-gnu'
  kernel32_pe_machine = 'arm64'
else
  error('Unsupported arch for kernel32.dll PE build: ' + arch)
endif

kernel32_pe_common_args = [
  '--edition=2024',
  '--target=' + kernel32_rust_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=small',
  '-C', 'relocation-model=pic',
]
if get_option('debug_symbols')
  kernel32_pe_common_args += ['-C', 'debuginfo=2']
endif

kernel32_core = custom_target('kernel32_core',
  input: [],
  output: ['core.o', 'libcore.rmeta'],
  command: [
    rustc,
    kernel32_pe_common_args,
    # Keeps default `core.*` intermediate prefix — that's fine because the
    # concurrent `--crate-name=core` builds (kernite `core_kernel`,
    # `trona_core`) now carry `-kernel` / `-trona` `extra-filename` suffixes
    # so their CGU temp files no longer share a filename prefix with this
    # build. `--out-dir` also isolates kernel32 intermediates under
    # `lib/trona/` regardless.
    '--emit=obj,metadata',
    '--out-dir', '@OUTDIR@',
    '--crate-name=core',
    '--crate-type=lib',
    rust_lib_src / 'core/src/lib.rs',
  ],
  build_by_default: true,
)

kernel32_compiler_builtins = custom_target('kernel32_compiler_builtins',
  input: files('compiler_builtins.rs'),
  output: ['compiler_builtins.o', 'libcompiler_builtins.rmeta'],
  command: [
    rustc,
    kernel32_pe_common_args,
    '--cfg', 'trona_mem_builtins',
    '--emit=obj,metadata',
    '--out-dir', '@OUTDIR@',
    '--crate-name=compiler_builtins',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + meson.current_build_dir() / 'libcore.rmeta',
    '-L', meson.current_build_dir(),
    '@INPUT@',
  ],
  depends: [kernel32_core],
  build_by_default: true,
)

# PE-target uapi rmeta — same bindgen source as `trona_uapi` (saltyos
# target), recompiled here for the PE target so kernel32.dll can import
# kernel ABI constants directly via `use uapi::*`. Replaces the
# `win32/trona.rs` mini-mirror that would otherwise drift from the
# canonical `kernite/include/uapi/*.h` headers.
uapi_pe = custom_target('uapi_pe',
  input: uapi_bindgen_rs,
  output: ['uapi-pe.o', 'libuapi-pe.rmeta'],
  command: [
    rustc,
    kernel32_pe_common_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=uapi',
    # Distinct rmeta filename from the saltyos-target `trona_uapi`
    # (which writes `libuapi.rmeta` into the same build dir).
    '-C', 'extra-filename=-pe',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + meson.current_build_dir() / 'libcore.rmeta',
    '--extern', 'compiler_builtins=' + meson.current_build_dir() / 'libcompiler_builtins.rmeta',
    '-L', meson.current_build_dir(),
    '@INPUT@',
  ],
  depends: [kernel32_core, kernel32_compiler_builtins, uapi_bindgen],
  build_by_default: true,
)

# PE-target trona_protocol rmeta — same source as `trona_protocol`
# (saltyos target), recompiled here for the PE target so kernel32.dll
# can `use trona_protocol::posix::*` directly. The crate's only
# `trona_kernel` dependency (`ensure_correlation_wire_length`) is gated
# behind `cfg(target_os = "saltyos")` and therefore disappears on this
# build, so trona_kernel itself does not need a PE rmeta — kernel32
# never stamps correlation headers.
trona_protocol_pe = custom_target('trona_protocol_pe',
  input: files('protocol/src/lib.rs'),
  output: ['trona_protocol-pe.o', 'libtrona_protocol-pe.rmeta'],
  command: [
    rustc,
    kernel32_pe_common_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=trona_protocol',
    # Distinct rmeta filename from the saltyos-target `trona_protocol`.
    '-C', 'extra-filename=-pe',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + meson.current_build_dir() / 'libcore.rmeta',
    '--extern', 'compiler_builtins=' + meson.current_build_dir() / 'libcompiler_builtins.rmeta',
    '--extern', 'uapi=' + meson.current_build_dir() / 'libuapi-pe.rmeta',
    '-L', meson.current_build_dir(),
    '@INPUT@',
  ],
  depends: [kernel32_core, kernel32_compiler_builtins, uapi_pe],
  build_by_default: true,
)

kernel32_pe_obj = custom_target('kernel32_pe_obj',
  input: files('win32/kernel32.rs'),
  output: 'kernel32.o',
  command: [
    rustc,
    kernel32_pe_common_args,
    '--emit=obj',
    '--out-dir', '@OUTDIR@',
    '--crate-name=kernel32',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + meson.current_build_dir() / 'libcore.rmeta',
    '--extern', 'compiler_builtins=' + meson.current_build_dir() / 'libcompiler_builtins.rmeta',
    '--extern', 'uapi=' + meson.current_build_dir() / 'libuapi-pe.rmeta',
    '--extern', 'trona_protocol=' + meson.current_build_dir() / 'libtrona_protocol-pe.rmeta',
    '-L', meson.current_build_dir(),
    '@INPUT@',
  ],
  depends: [kernel32_core, kernel32_compiler_builtins, uapi_pe, trona_protocol_pe],
  build_by_default: true,
)

kernel32_syscall_obj = custom_target('kernel32_syscall_asm',
  input: files('win32/arch' / arch / 'syscall.S'),
  output: 'kernel32_syscall.obj',
  command: [cc_cmd, '--target=' + kernel32_asm_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

kernel32_dll = custom_target('kernel32_dll',
  input: [kernel32_pe_obj, kernel32_syscall_obj, kernel32_core[0], kernel32_compiler_builtins[0], uapi_pe[0], trona_protocol_pe[0], files('win32/kernel32.def')],
  output: 'kernel32.dll',
  command: [lld_link,
    '-dll',
    '-noentry',
    '-nodefaultlib',
    '-machine:' + kernel32_pe_machine,
    '-def:@INPUT6@',
    '-out:@OUTPUT@',
    '@INPUT0@',
    '@INPUT1@',
    '@INPUT2@',
    '@INPUT3@',
    '@INPUT4@',
    '@INPUT5@',
  ],
  build_by_default: true,
)

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
  input: [trona_kernel_obj, trona_protocol_obj, trona_server_obj, trona_runtime_obj,
          trona_posix_obj, trona_loader_obj, trona_uapi_obj,
          trona_kernel_syscall_obj, trona_runtime_tls_obj, trona_runtime_thread_obj,
          trona_pthread_obj, fork_obj, core_obj, compiler_builtins_obj],
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

libtrona_a = custom_target('libtrona_a',
  input: [trona_kernel_obj, trona_protocol_obj, trona_server_obj, trona_runtime_obj,
          trona_posix_obj, trona_loader_obj, trona_uapi_obj,
          trona_kernel_syscall_obj, trona_runtime_tls_obj, trona_runtime_thread_obj,
          trona_pthread_obj, fork_obj, core_obj, compiler_builtins_obj],
  output: 'libtrona.a',
  command: [llvm_ar, 'rcs', '@OUTPUT@', '@INPUT@'],
  build_by_default: true,
)

# =============================================================================
# Runtime dynamic linker (ldtrona-elf.so, ldtrona-pe.so)
# =============================================================================

subdir('loader')

# =============================================================================
# Exported variables for downstream consumers (userland, top-level meson.build)
# =============================================================================
#
# Build directory / path strings:
#   libtrona_build_dir   — build directory path (for -L flags)
#   trona_uapi_rmeta     — path string for --extern uapi=...
#   trona_kernel_rmeta   — path string for --extern trona_kernel=...
#   trona_protocol_rmeta — path string for --extern trona_protocol=...
#   trona_server_rmeta   — path string for --extern trona_server=...
#   trona_runtime_rmeta  — path string for --extern trona_runtime=...
#   trona_posix_rmeta    — path string for --extern trona_posix=...
#
# Custom targets (for depends/input):
#   libtrona_so          — libtrona.so shared library (5 trona crates + posix + loader)
#   ld_trona_so          — ldtrona-elf.so dynamic linker (from loader/)
#   fork_obj             — fork assembly object (for init static link)
#   trona_uapi           — uapi crate
#   trona_kernel         — trona_kernel crate
#   trona_protocol       — trona_protocol crate
#   trona_server         — trona_server crate
#   trona_runtime        — trona_runtime crate
#
# Individual .o files (for init static link):
#   trona_kernel_obj     — trona_kernel .o
#   trona_protocol_obj   — trona_protocol .o
#   trona_server_obj     — trona_server .o
#   trona_runtime_obj    — trona_runtime .o (carries the C-ABI exports + weak symbols)
#   trona_posix_obj      — trona_posix .o
#   trona_loader_obj     — trona_loader .o
