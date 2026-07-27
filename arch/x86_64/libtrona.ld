/* libtrona.so linker script
 * SPDX-License-Identifier: GPL-2.0-only
 */

OUTPUT_FORMAT("elf64-x86-64")
SECTIONS {
    . = SIZEOF_HEADERS;
    .gnu.hash     : { *(.gnu.hash) }
    .dynsym       : { *(.dynsym) }
    .dynstr       : { *(.dynstr) }
    .rela.dyn     : { *(.rela.dyn) }
    .rela.plt     : { *(.rela.plt) }

    .plt ALIGN(4K) : { *(.plt .plt.*) }

    .text ALIGN(4K) : {
        *(.init .init.*)
        *(.text .text.*)
        *(.fini .fini.*)
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.gnu.linkonce.r.*)
    }

    .data.rel.ro ALIGN(4K) : {
        *(.data.rel.ro.local .data.rel.ro.local.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.gnu.linkonce.d.rel.ro.*)
    }

    .got      : { *(.got .igot) }
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
    .got.plt ALIGN(4K) : { *(.got.plt) }

    .data ALIGN(4K) : {
        *(.data .data.*)
        *(.data.rel.local .data.rel.local.*)
        *(.data.rel .data.rel.*)
        *(.sdata .sdata.*)
    }

    .tdata ALIGN(16) : { *(.tdata .tdata.*) }
    .tbss           : { *(.tbss .tbss.*) *(.tcommon) }

    .bss ALIGN(4K) : {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    }
    /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame*) }
}
