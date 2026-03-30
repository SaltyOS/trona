# trona-uapi — shared userspace/kernel contract surface
# SPDX-License-Identifier: GPL-2.0-only

trona_uapi_inc = include_directories('include')
trona_uapi_inc_dir = meson.current_source_dir() / 'include'
trona_uapi_rust_consts = meson.current_source_dir() / 'rust' / 'consts.rs'

_trona_uapi_hdr_list = run_command(
  'find', 'include', '-name', '*.h',
  capture: true, check: true,
).stdout().strip()

trona_uapi_header_files = []
if _trona_uapi_hdr_list != ''
  foreach h : _trona_uapi_hdr_list.split('\n')
    trona_uapi_header_files += files(h)
  endforeach
endif
