# trona_loader — Unified ELF/PE loader and RTLD
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds:
#   1. libtrona_loader.{o,rmeta}  — common/ modules, linked into libtrona.so
#   2. ldtrona-elf.so             — ELF RTLD binary (common + rtld + asm)
#   3. ldtrona-pe.so              — PE RTLD binary  (common + rtld + asm)

loader_src_dir = meson.current_source_dir()
loader_build_dir = meson.current_build_dir()

# =============================================================================
# 1. common/ compilation (shared by libtrona.so and ldtrona)
# =============================================================================
# This is handled by the parent meson.build (lib/trona/meson.build) which
# compiles loader/lib.rs → libtrona_loader.o + libtrona_loader.rmeta.
# The parent target already includes common/ via the crate root.

# =============================================================================
# 2. RTLD Rust compilation (rtld/ modules → .o)
# =============================================================================
# libtrona.so only links the common/ subset. The actual RTLD binary gets its
# own loader object built with --cfg rtld_binary so that rtld/ code and its
# trampoline symbols stay out of libtrona.so.

trona_loader_rtld = custom_target('trona_loader_rtld',
    input: files('lib.rs'),
    output: ['ldtrona_loader.o', 'ldtrona_loader.rmeta'],
    depfile: 'ldtrona_loader.d',
    command: [rustc,
        rust_userland_args,
        '--cfg', 'rtld_binary',
        '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
        '--crate-name=trona_loader_rtld',
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

trona_loader_rtld_obj = trona_loader_rtld[0]

# =============================================================================
# 3. Assembly — arch-specific entry point and PLT resolver
# =============================================================================

ldtrona_start_obj = custom_target('ldtrona_start_asm',
    input: files('rtld/arch' / arch / 'start.S'),
    output: 'ldtrona_start.o',
    command: [cc_cmd, '--target=' + c_target, '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
)

# TLSDESC resolver trampolines — one per arch. Linked into both
# ldtrona-elf.so and ldtrona-pe.so so the dlopen path can write the
# resolver pointer into TLSDESC GOT slots without taking a runtime
# dependency on libtrona.so.
ldtrona_tlsdesc_obj = custom_target('ldtrona_tlsdesc_asm',
    input: files('rtld/arch' / arch / 'tlsdesc.S'),
    output: 'ldtrona_tlsdesc.o',
    command: [cc_cmd, '--target=' + c_target, '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
)

ldtrona_syscall_obj = custom_target('ldtrona_syscall_asm',
    input: files('rtld/arch' / arch / 'syscall.S'),
    output: 'ldtrona_syscall.o',
    command: [cc_cmd, '--target=' + c_target, '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
)

# =============================================================================
# 4. Link ldtrona-elf.so
# =============================================================================

ldtrona_elf_link = loader_src_dir / 'rtld/arch' / arch / 'ldtrona-elf.ld'

ld_trona_so = custom_target('ld_trona_so',
    input: [trona_loader_rtld_obj,
            trona_kernel_obj, trona_protocol_obj, trona_server_obj, trona_runtime_obj,
            trona_uapi_obj,
            trona_kernel_syscall_obj, trona_runtime_tls_obj, trona_runtime_thread_obj,
            ldtrona_start_obj, ldtrona_tlsdesc_obj, ldtrona_syscall_obj, core_obj,
            compiler_builtins_rtld_obj],
    output: 'ldtrona-elf.so',
    command: [cc_cmd,
        '--target=' + c_target,
        '-nostdlib', '-nostartfiles',
        '-fno-stack-protector',
        '-Wl,-Bsymbolic',
        '-T', ldtrona_elf_link,
        '-Wl,-soname,ldtrona-elf.so',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    depends: [trona_loader_rtld, trona_uapi],
    build_by_default: true,
)

# =============================================================================
# 5. Link ldtrona-pe.so
# =============================================================================

ldtrona_pe_link = loader_src_dir / 'rtld/arch' / arch / 'ldtrona-pe.ld'

ld_trona_pe_so = custom_target('ld_trona_pe_so',
    input: [trona_loader_rtld_obj,
            trona_kernel_obj, trona_protocol_obj, trona_server_obj, trona_runtime_obj,
            trona_uapi_obj,
            trona_kernel_syscall_obj, trona_runtime_tls_obj, trona_runtime_thread_obj,
            ldtrona_start_obj, ldtrona_tlsdesc_obj, ldtrona_syscall_obj, core_obj,
            compiler_builtins_rtld_obj],
    output: 'ldtrona-pe.so',
    command: [cc_cmd,
        '--target=' + c_target,
        '-nostdlib', '-nostartfiles',
        '-fno-stack-protector',
        '-Wl,-Bsymbolic',
        '-T', ldtrona_pe_link,
        '-Wl,-soname,ldtrona-pe.so',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    depends: [trona_loader_rtld, trona_uapi],
    build_by_default: true,
)
