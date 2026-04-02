# SaltyOS PE Runtime Loader Build
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds ld-trona-pe.so as a static PIE with no external dependencies.
# Follows the same pattern as the ELF rtld (rtld/elf/meson.build).

pe_rtld_c_sources = files(
    'rtld_pe_main.c',
)
pe_rtld_link_script = meson.current_source_dir() / 'arch' / arch / 'rtld_pe.ld'

pe_rtld_c_args = [
    '--target=' + c_target,
    '-ffreestanding',
    '-fPIC',
    '-fno-plt',
    '-fno-stack-protector',
    '-I', meson.current_source_dir(),
]

# Step 1: Compile C source with depfile for header tracking
pe_rtld_objs = []
foreach src : pe_rtld_c_sources
  src_name = fs.name(src)
  obj_name = 'pe_rtld_' + src_name.replace('.c', '.o')
  dep_name = 'pe_rtld_' + src_name.replace('.c', '.d')
  pe_rtld_objs += custom_target(obj_name,
    input: src,
    output: obj_name,
    depfile: dep_name,
    command: [cc_cmd, pe_rtld_c_args, '-MMD', '-MF', '@DEPFILE@',
             '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
endforeach

# Step 2: Link ld-trona-pe.so
ld_trona_pe_so = custom_target('ld_trona_pe_so',
    input: pe_rtld_objs,
  output: 'ld-trona-pe.so',
    command: [cc_cmd,
        '--target=' + c_target,
        '-nostdlib', '-nostartfiles',
        '-fno-stack-protector',
        '-Wl,-Bsymbolic',
        '-T', pe_rtld_link_script,
    '-Wl,-soname,ld-trona-pe.so',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
