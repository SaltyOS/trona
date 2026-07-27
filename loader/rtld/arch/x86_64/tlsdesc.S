// SPDX-License-Identifier: GPL-2.0-only
// TLSDESC resolver trampolines (x86_64).
//
// The compiler-generated code at every TLSDESC callsite loads the descriptor
// address into %rax and calls *(%rax). The resolver receives %rax as the
// descriptor pointer and must return the TP-relative offset in %rax.
// Caller-saved registers other than %rax MUST be preserved — the AMD64
// TLSDESC ABI mandates that the only clobbered registers are %rax and CC.
//
// `_dl_tlsdesc_static_resolver`  — descriptor[1] holds the static TP-relative
//                                  offset; just load and return.
// `_dl_tlsdesc_dynamic_resolver` — descriptor[1] is a `TlsDescDyn*` (declared
//                                  in lib/trona/loader/rtld/elf/tls.rs);
//                                  call into the Rust resolver and return
//                                  the offset it produces.

    .text

    .globl _dl_tlsdesc_static_resolver
    .type _dl_tlsdesc_static_resolver, @function
    .p2align 4
_dl_tlsdesc_static_resolver:
    movq 8(%rax), %rax
    ret
    .size _dl_tlsdesc_static_resolver, .-_dl_tlsdesc_static_resolver

    .globl _dl_tlsdesc_dynamic_resolver
    .type _dl_tlsdesc_dynamic_resolver, @function
    .p2align 4
_dl_tlsdesc_dynamic_resolver:
    // Save every caller-saved GPR except %rax (the return register).
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    subq $8, %rsp                   // 16-byte stack alignment for call

    movq 8(%rax), %rdi              // arg = descriptor[1] = *TlsDescDyn
    call __rtld_tlsdesc_resolve_dynamic

    addq $8, %rsp
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    ret
    .size _dl_tlsdesc_dynamic_resolver, .-_dl_tlsdesc_dynamic_resolver

    .section .note.GNU-stack, "", @progbits
