# Runtime dynamic linker — format-specific subdirectories
# SPDX-License-Identifier: GPL-2.0-only

# Generated `cap_table_roles.h` + `role_map_data.py` from the single
# source of truth (`lib/trona/uapi/consts/kernel.rs`). Re-runs whenever
# the input changes; downstream rtld C files pick up the regenerated
# header via `-I` below and meson depfile tracking.
py_prog = find_program('python3')
role_map_gen = custom_target('role_map_gen',
  input:  files('../uapi/consts/kernel.rs'),
  output: ['cap_table_roles.h', 'role_map_data.py'],
  command: [py_prog, files('../../../tools/role_map_gen.py'),
            '--input', '@INPUT@',
            '--c-output', '@OUTPUT0@',
            '--py-output', '@OUTPUT1@'],
  build_by_default: true,
)
# Build-directory path containing the generated header. Both ELF and PE
# rtld subdirs add this to their compile `-I` list.
rtld_generated_dir = meson.current_build_dir()
# Path to the generated role_map_data.py, exposed for svc_caps_gen.py.
# Use the explicit string path (not the CustomTargetIndex) so meson hands a
# stable absolute path to downstream `command:` arrays. Consumers must add
# `depends: [role_map_gen]` to enforce ordering.
role_map_data_py = rtld_generated_dir / 'role_map_data.py'

subdir('elf')
subdir('pe')
