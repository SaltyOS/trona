/* ldtrona-elf.so linker script — x86_64
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Produces a static PIE (ET_DYN with entry point, no interpreter).
 * Base address 0 — relocated at load time by self_relocate().
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = SIZEOF_HEADERS;

    /* Metadata in the header page — keeps ELF header in PT_LOAD */
    .gnu.hash : { *(.gnu.hash) }
    .dynsym   : { *(.dynsym) }
    .dynstr   : { *(.dynstr) }
    .rela.dyn : { *(.rela.dyn) *(.rela.plt) }

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
    .got.plt  : { *(.got.plt) }

    .bss ALIGN(4K) : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.interp)
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
