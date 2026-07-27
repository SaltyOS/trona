// SPDX-License-Identifier: GPL-2.0-only
// TLSDESC resolver trampolines (aarch64).
//
// The compiler-generated TLSDESC callsite loads the descriptor address into
// x0 and calls the resolver. The resolver receives x0 as the descriptor
// pointer and must return the TP-relative offset in x0. The AAPCS64 TLSDESC
// amendment requires the resolver to preserve every register other than x0
// and condition flags.
//
// `_dl_tlsdesc_static_resolver`  — descriptor[1] holds the static TP-relative
//                                  offset; just load and return.
// `_dl_tlsdesc_dynamic_resolver` — descriptor[1] is a `TlsDescDyn*` (declared
//                                  in lib/trona/loader/rtld/elf/tls.rs);
//                                  bridge into the Rust dynamic resolver.

    .text

    .globl _dl_tlsdesc_static_resolver
    .type _dl_tlsdesc_static_resolver, %function
    .p2align 2
_dl_tlsdesc_static_resolver:
    ldr x0, [x0, #8]
    ret
    .size _dl_tlsdesc_static_resolver, .-_dl_tlsdesc_static_resolver

    .globl _dl_tlsdesc_dynamic_resolver
    .type _dl_tlsdesc_dynamic_resolver, %function
    .p2align 2
_dl_tlsdesc_dynamic_resolver:
    // AAPCS64 TLSDESC ABI: preserve every register the caller might be
    // using except x0 (the return register). That includes the full
    // NEON / SIMD register file (q0..q31), since TLS access can legitimately
    // appear inside vectorised hot loops.
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x1, x2,   [sp, #-16]!
    stp x3, x4,   [sp, #-16]!
    stp x5, x6,   [sp, #-16]!
    stp x7, x8,   [sp, #-16]!
    stp x9, x10,  [sp, #-16]!
    stp x11, x12, [sp, #-16]!
    stp x13, x14, [sp, #-16]!
    stp x15, x16, [sp, #-16]!
    str x17,      [sp, #-16]!     // x17 is single, pad to 16-byte alignment

    // 32 q-registers × 16 bytes = 512 bytes, saved as 16 stp pairs.
    stp q0,  q1,  [sp, #-32]!
    stp q2,  q3,  [sp, #-32]!
    stp q4,  q5,  [sp, #-32]!
    stp q6,  q7,  [sp, #-32]!
    stp q8,  q9,  [sp, #-32]!
    stp q10, q11, [sp, #-32]!
    stp q12, q13, [sp, #-32]!
    stp q14, q15, [sp, #-32]!
    stp q16, q17, [sp, #-32]!
    stp q18, q19, [sp, #-32]!
    stp q20, q21, [sp, #-32]!
    stp q22, q23, [sp, #-32]!
    stp q24, q25, [sp, #-32]!
    stp q26, q27, [sp, #-32]!
    stp q28, q29, [sp, #-32]!
    stp q30, q31, [sp, #-32]!

    ldr x0, [x0, #8]              // arg = descriptor[1] = *TlsDescDyn
    bl __rtld_tlsdesc_resolve_dynamic

    ldp q30, q31, [sp], #32
    ldp q28, q29, [sp], #32
    ldp q26, q27, [sp], #32
    ldp q24, q25, [sp], #32
    ldp q22, q23, [sp], #32
    ldp q20, q21, [sp], #32
    ldp q18, q19, [sp], #32
    ldp q16, q17, [sp], #32
    ldp q14, q15, [sp], #32
    ldp q12, q13, [sp], #32
    ldp q10, q11, [sp], #32
    ldp q8,  q9,  [sp], #32
    ldp q6,  q7,  [sp], #32
    ldp q4,  q5,  [sp], #32
    ldp q2,  q3,  [sp], #32
    ldp q0,  q1,  [sp], #32

    ldr x17,      [sp], #16
    ldp x15, x16, [sp], #16
    ldp x13, x14, [sp], #16
    ldp x11, x12, [sp], #16
    ldp x9, x10,  [sp], #16
    ldp x7, x8,   [sp], #16
    ldp x5, x6,   [sp], #16
    ldp x3, x4,   [sp], #16
    ldp x1, x2,   [sp], #16
    ldp x29, x30, [sp], #16
    ret
    .size _dl_tlsdesc_dynamic_resolver, .-_dl_tlsdesc_dynamic_resolver

    .section .note.GNU-stack, "", %progbits
