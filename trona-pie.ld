/* Trona PIE executable linker script
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Used by the Trona driver for position-independent executables.
 * Propagated to the sysroot (cross-compilation) and rootfs (on-target).
 */

ENTRY(_start)

SECTIONS
{
    . = SIZEOF_HEADERS;

    .interp       : { *(.interp) }
    .gnu.hash     : { *(.gnu.hash) }
    .dynsym       : { *(.dynsym) }
    .dynstr       : { *(.dynstr) }
    .rela.dyn     : { *(.rela.dyn) }
    .rela.plt     : { *(.rela.plt) }

    .plt ALIGN(16) : { *(.plt .plt.*) }

    .text ALIGN(4K) : {
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4K) : {
        *(.data .data.*)
    }

    .got      : { *(.got) }
    .dynamic  : { *(.dynamic) }
    .preinit_array : {
        PROVIDE(__preinit_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.preinit_array.*)))
        KEEP(*(.preinit_array))
        PROVIDE(__preinit_array_end = .);
    }
    .init_array : {
        PROVIDE(__init_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE(__init_array_end = .);
    }
    .fini_array : {
        PROVIDE(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
        KEEP(*(.fini_array))
        PROVIDE(__fini_array_end = .);
    }
    .got.plt  : { *(.got.plt) }

    .bss ALIGN(4K) : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
