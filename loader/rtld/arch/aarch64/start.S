/* ldtrona-elf.so — AArch64 entry and PLT resolver
 * SPDX-License-Identifier: GPL-2.0-only
 */

.text

/* _start — RTLD entry point.
 * Stack holds argc/argv/envp/auxv per AArch64 ABI.
 */
.globl _start
.type _start, @function
_start:
    mov     x29, xzr
    mov     x30, xzr
    mov     x19, sp             /* save original SP */

    /* Self-relocate: x0 = _DYNAMIC, x1 = load base */
    adrp    x0, _DYNAMIC
    add     x0, x0, :lo12:_DYNAMIC
    adrp    x1, __ehdr_start
    add     x1, x1, :lo12:__ehdr_start

    bl      self_relocate

    mov     x0, x19             /* sp = original stack pointer */
    bl      rtld_main           /* returns app entry in x0 */

    mov     x1, x0              /* entry */
    mov     x0, x19             /* sp */
    b       rtld_jump_entry

.size _start, . - _start

/* _dl_runtime_resolve — AArch64 PLT lazy resolver trampoline.
 *
 * AArch64 ELF PLT ABI:
 * - PLT[n] enters PLT0 with x16 = &GOT[n]
 * - PLT0 pushes {x16, x30}, then x16 = &GOT[2], x17 = resolver
 * - GOT[1] = link_map*, GOT[2] = _dl_runtime_resolve
 */
.globl _dl_runtime_resolve
.type _dl_runtime_resolve, @function

_dl_runtime_resolve:
    ldr     x9, [sp]            /* saved GOT[n] address */
    ldr     x10, [x16, #-8]    /* GOT[1] = link_map* */
    sub     x11, x9, x16       /* GOT[n] - GOT[2] */
    sub     x11, x11, #8       /* index from GOT[3] */
    lsr     x11, x11, #3       /* 8-byte entries -> reloc index */

    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!
    stp     x29, x30, [sp, #-16]!

    mov     x0, x10             /* link_map* */
    mov     x1, x11             /* reloc_index */
    bl      _dl_fixup
    mov     x16, x0

    ldp     x29, x30, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16

    /* Drop PLT0's {x16, x30} frame */
    add     sp, sp, #16

    br      x16

.size _dl_runtime_resolve, . - _dl_runtime_resolve

/* TLSDESC static resolver.
 * On entry: x0 = &descriptor{resolver, arg}.
 * Returns TP-relative offset in x0.
 */
.globl _tlsdesc_static_resolver
.type _tlsdesc_static_resolver, @function

_tlsdesc_static_resolver:
    ldr     x0, [x0, #8]
    ret

.size _tlsdesc_static_resolver, . - _tlsdesc_static_resolver

/* rtld_jump_entry — transfer control to the application.
 * Arguments: x0 = sp, x1 = entry.  Does not return.
 */
.globl rtld_jump_entry
.type rtld_jump_entry, @function

rtld_jump_entry:
    dsb     ish
    isb
    mov     sp, x0
    mov     x29, xzr
    mov     x30, xzr
    br      x1

.size rtld_jump_entry, . - rtld_jump_entry

/* self_relocate — process R_RELATIVE relocations for the RTLD itself.
 * Arguments: x0 = _DYNAMIC address, x1 = load base.
 */
.globl self_relocate
.type self_relocate, @function

self_relocate:
    mov     x2, xzr             /* rela = 0 */
    mov     x3, xzr             /* relasz = 0 */

.Lscan_dyn:
    ldr     x4, [x0]            /* d_tag */
    cbz     x4, .Ldo_relocs
    cmp     x4, #7              /* DT_RELA */
    b.eq    .Lgot_rela
    cmp     x4, #8              /* DT_RELASZ */
    b.eq    .Lgot_relasz
    add     x0, x0, #16
    b       .Lscan_dyn

.Lgot_rela:
    ldr     x2, [x0, #8]
    add     x2, x2, x1          /* rela = base + d_val */
    add     x0, x0, #16
    b       .Lscan_dyn

.Lgot_relasz:
    ldr     x3, [x0, #8]
    add     x0, x0, #16
    b       .Lscan_dyn

.Ldo_relocs:
    cbz     x2, .Ldone
    cbz     x3, .Ldone

.Lreloc_loop:
    cmp     x3, #0
    b.le    .Ldone
    ldr     w4, [x2, #8]        /* r_info low 32 = type */
    mov     w5, #1027            /* R_AARCH64_RELATIVE */
    cmp     w4, w5
    b.ne    .Lskip
    ldr     x6, [x2]            /* r_offset */
    add     x6, x6, x1          /* target = base + r_offset */
    ldr     x7, [x2, #16]       /* r_addend */
    add     x7, x7, x1          /* value = base + r_addend */
    str     x7, [x6]
.Lskip:
    add     x2, x2, #24
    sub     x3, x3, #24
    b       .Lreloc_loop

.Ldone:
    ret

.size self_relocate, . - self_relocate
