/* ldtrona-elf.so — x86_64 entry and PLT resolver
 * SPDX-License-Identifier: GPL-2.0-only
 */

.text

/* _start — RTLD entry point.
 * Stack holds argc/argv/envp/auxv per SysV ABI.
 * Self-relocate, then call rtld_main(sp) which returns the app entry.
 */
.globl _start
.type _start, @function
_start:
    xor     %ebp, %ebp
    mov     %rsp, %rbx          /* save original SP */
    andq    $-16, %rsp

    /* Compute own load base: _DYNAMIC is a linker-provided symbol
     * whose link-time value is its offset from base. */
    leaq    _DYNAMIC(%rip), %rdi        /* actual address of _DYNAMIC */
    leaq    __ehdr_start(%rip), %rsi    /* actual load base */

    call    self_relocate

    mov     %rbx, %rdi           /* sp = original stack pointer */
    call    rtld_main            /* returns app entry in %rax */

    mov     %rbx, %rdi           /* sp for rtld_jump_entry */
    mov     %rax, %rsi           /* entry */
    movq    rtld_pe_image_kind(%rip), %rcx
    cmpq    %rcx, rtld_startup_image_kind(%rip)
    je      rtld_jump_entry_win64
    jmp     rtld_jump_entry

.size _start, . - _start

/* _dl_runtime_resolve — PLT lazy resolver trampoline.
 *
 * Saves all caller-saved GPRs AND XMM0-XMM7 so that lazy resolution
 * is transparent to calling code (including SSE/float arguments).
 *
 * Stack layout after full save (offsets from RSP):
 *   0-127  : XMM0-XMM7 (8 * 16 bytes)
 *   128-199: GPRs r11,r10,r9,r8,rdi,rsi,rdx,rcx,rax (9 * 8 bytes)
 *   200    : link_map*    (pushed by PLT[0])
 *   208    : reloc_index  (pushed by PLT[N] stub)
 *   216    : return addr  (pushed by original call)
 */
.globl _dl_runtime_resolve
.type _dl_runtime_resolve, @function

_dl_runtime_resolve:
    pushq   %rax
    pushq   %rcx
    pushq   %rdx
    pushq   %rsi
    pushq   %rdi
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11

    subq    $128, %rsp
    movdqu  %xmm0,   0(%rsp)
    movdqu  %xmm1,  16(%rsp)
    movdqu  %xmm2,  32(%rsp)
    movdqu  %xmm3,  48(%rsp)
    movdqu  %xmm4,  64(%rsp)
    movdqu  %xmm5,  80(%rsp)
    movdqu  %xmm6,  96(%rsp)
    movdqu  %xmm7, 112(%rsp)

    movq    200(%rsp), %rdi     /* link_map* */
    movq    208(%rsp), %rsi     /* reloc_index */

    call    _dl_fixup

    movq    %rax, 200(%rsp)     /* overwrite link_map slot with result */

    movdqu    0(%rsp), %xmm0
    movdqu   16(%rsp), %xmm1
    movdqu   32(%rsp), %xmm2
    movdqu   48(%rsp), %xmm3
    movdqu   64(%rsp), %xmm4
    movdqu   80(%rsp), %xmm5
    movdqu   96(%rsp), %xmm6
    movdqu  112(%rsp), %xmm7
    addq    $128, %rsp

    popq    %r11
    popq    %r10
    popq    %r9
    popq    %r8
    popq    %rdi
    popq    %rsi
    popq    %rdx
    popq    %rcx
    popq    %rax

    ret     $8

.size _dl_runtime_resolve, . - _dl_runtime_resolve

/* TLSDESC static resolver.
 * On entry: %rax = &descriptor{resolver, arg}.
 * Returns TP-relative offset in %rax.
 */
.globl _tlsdesc_static_resolver
.type _tlsdesc_static_resolver, @function

_tlsdesc_static_resolver:
    movq    8(%rax), %rax
    ret

.size _tlsdesc_static_resolver, . - _tlsdesc_static_resolver

/* rtld_jump_entry — transfer control to the application.
 * Arguments: rdi = sp, rsi = entry.  Does not return.
 */
.globl rtld_jump_entry
.type rtld_jump_entry, @function

rtld_jump_entry:
    movq    %rdi, %rsp
    xorq    %rbp, %rbp
    jmpq    *%rsi

.size rtld_jump_entry, . - rtld_jump_entry

/* rtld_jump_entry_win64 — transfer control to a PE/COFF x86_64 entry.
 * Arguments: rdi = original startup sp, rsi = entry. Does not return.
 *
 * Win64 callees enter with RSP % 16 == 8 and with 32 bytes of caller-owned
 * shadow space at [RSP+8, RSP+40). A raw jump from the ELF-shaped startup
 * stack leaves RSP % 16 == 0, so compiler-generated `movaps` spills fault.
 */
.globl rtld_jump_entry_win64
.type rtld_jump_entry_win64, @function

rtld_jump_entry_win64:
    movq    %rdi, %rsp
    andq    $-16, %rsp
    subq    $32, %rsp
    xorq    %rbp, %rbp
    callq   *%rsi
    ud2

.size rtld_jump_entry_win64, . - rtld_jump_entry_win64

/* self_relocate — process R_RELATIVE relocations for the RTLD itself.
 * Arguments: rdi = _DYNAMIC address, rsi = load base.
 * Called before any global data is usable.
 */
.globl self_relocate
.type self_relocate, @function

self_relocate:
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    movq    %rsi, %r12          /* r12 = base */
    xorq    %rbx, %rbx          /* rela = 0 */
    xorq    %r13, %r13          /* relasz = 0 */

.Lscan_dyn:
    movq    0(%rdi), %rax       /* d_tag */
    testq   %rax, %rax
    jz      .Ldo_relocs
    cmpq    $7, %rax            /* DT_RELA */
    je      .Lgot_rela
    cmpq    $8, %rax            /* DT_RELASZ */
    je      .Lgot_relasz
    addq    $16, %rdi
    jmp     .Lscan_dyn

.Lgot_rela:
    movq    8(%rdi), %rbx
    addq    %r12, %rbx          /* rela = base + d_val */
    addq    $16, %rdi
    jmp     .Lscan_dyn

.Lgot_relasz:
    movq    8(%rdi), %r13
    addq    $16, %rdi
    jmp     .Lscan_dyn

.Ldo_relocs:
    testq   %rbx, %rbx
    jz      .Ldone
    testq   %r13, %r13
    jz      .Ldone

.Lreloc_loop:
    cmpq    $0, %r13
    jle     .Ldone
    movl    8(%rbx), %eax       /* r_info low 32 = type */
    cmpl    $8, %eax            /* R_X86_64_RELATIVE */
    jne     .Lskip
    movq    0(%rbx), %rcx       /* r_offset */
    addq    %r12, %rcx          /* target = base + r_offset */
    movq    16(%rbx), %rdx      /* r_addend */
    addq    %r12, %rdx          /* value = base + r_addend */
    movq    %rdx, (%rcx)
.Lskip:
    addq    $24, %rbx           /* sizeof(Elf64_Rela) */
    subq    $24, %r13
    jmp     .Lreloc_loop

.Ldone:
    popq    %r13
    popq    %r12
    popq    %rbx
    ret

.size self_relocate, . - self_relocate
