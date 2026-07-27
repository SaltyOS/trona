/* SaltyOS static PIE executable linker script
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Used by static processes entered directly by the kernel or by an
 * existing spawner. The image is ET_DYN with virtual base 0; the loader
 * maps it at the chosen base and jumps to _start.
 */

ENTRY(_start)

SECTIONS
{
    . = 0;

    .text ALIGN(4K) : {
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    .rela.dyn : { *(.rela.dyn) *(.rela.plt) }

    .data.rel.ro ALIGN(8) : {
        *(.data.rel.ro .data.rel.ro.*)
    }

    .dynamic : { *(.dynamic) }
    .got : { *(.got) }
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

    .got.plt : { *(.got.plt) }

    . = ALIGN(4K);

    .data : {
        *(.data .data.*)
    }

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
