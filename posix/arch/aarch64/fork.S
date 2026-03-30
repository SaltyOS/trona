/* SaltyOS fork() assembly trampoline (AArch64)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * posix_fork() saves callee-saved GPRs and ALL NEON registers on the stack,
 * then calls _posix_fork_impl() which sends PM_FORK to procmgr with the
 * current SP and the address of fork_child_entry.
 *
 * _posix_fork_impl() is a Rust function that freely uses caller-saved NEON
 * registers (D0-D7, D16-D31) for struct copies and IPC message construction.
 * We must save ALL Q0-Q31 before the call so the parent's and child's NEON
 * state is preserved across fork — matching the x86_64 fork.S which saves
 * XMM0-XMM15 under SALTY_X86_SIMD.
 *
 * Parent path: _posix_fork_impl returns child PID, we restore all regs.
 * Child path: procmgr sets child RIP to fork_child_entry with saved SP.
 */

.text
.global posix_fork
.global fork_child_entry
.hidden fork_child_entry

posix_fork:
    /* Save callee-saved GPRs (x19-x28, x29/FP, x30/LR) */
    stp     x29, x30, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x19, x20, [sp, #-16]!

    /* Save ALL NEON/FP regs (Q0-Q31 = 512 bytes).
     * _posix_fork_impl() clobbers caller-saved D0-D7/D16-D31 for struct
     * operations, and the kernel saves that clobbered state to the FPU
     * buffer during the IPC context switch. We save the full register
     * file here so both parent and child can restore the pre-fork state. */
    sub     sp, sp, #512
    stp     q0,  q1,  [sp, #0]
    stp     q2,  q3,  [sp, #32]
    stp     q4,  q5,  [sp, #64]
    stp     q6,  q7,  [sp, #96]
    stp     q8,  q9,  [sp, #128]
    stp     q10, q11, [sp, #160]
    stp     q12, q13, [sp, #192]
    stp     q14, q15, [sp, #224]
    stp     q16, q17, [sp, #256]
    stp     q18, q19, [sp, #288]
    stp     q20, q21, [sp, #320]
    stp     q22, q23, [sp, #352]
    stp     q24, q25, [sp, #384]
    stp     q26, q27, [sp, #416]
    stp     q28, q29, [sp, #448]
    stp     q30, q31, [sp, #480]

    /* Call _posix_fork_impl(saved_sp, child_entry) */
    mov     x0, sp
    adrp    x1, fork_child_entry
    add     x1, x1, :lo12:fork_child_entry
    bl      _posix_fork_impl

    /* Parent: restore ALL NEON/FP regs */
    ldp     q0,  q1,  [sp, #0]
    ldp     q2,  q3,  [sp, #32]
    ldp     q4,  q5,  [sp, #64]
    ldp     q6,  q7,  [sp, #96]
    ldp     q8,  q9,  [sp, #128]
    ldp     q10, q11, [sp, #160]
    ldp     q12, q13, [sp, #192]
    ldp     q14, q15, [sp, #224]
    ldp     q16, q17, [sp, #256]
    ldp     q18, q19, [sp, #288]
    ldp     q20, q21, [sp, #320]
    ldp     q22, q23, [sp, #352]
    ldp     q24, q25, [sp, #384]
    ldp     q26, q27, [sp, #416]
    ldp     q28, q29, [sp, #448]
    ldp     q30, q31, [sp, #480]
    add     sp, sp, #512

    /* Parent: restore GPRs */
    ldp     x19, x20, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x29, x30, [sp], #16

    /* Return child PID (already in x0 from _posix_fork_impl) */
    ret

fork_child_entry:
    /* Child starts here with SP pointing to saved state */

    /* Restore ALL NEON/FP regs */
    ldp     q0,  q1,  [sp, #0]
    ldp     q2,  q3,  [sp, #32]
    ldp     q4,  q5,  [sp, #64]
    ldp     q6,  q7,  [sp, #96]
    ldp     q8,  q9,  [sp, #128]
    ldp     q10, q11, [sp, #160]
    ldp     q12, q13, [sp, #192]
    ldp     q14, q15, [sp, #224]
    ldp     q16, q17, [sp, #256]
    ldp     q18, q19, [sp, #288]
    ldp     q20, q21, [sp, #320]
    ldp     q22, q23, [sp, #352]
    ldp     q24, q25, [sp, #384]
    ldp     q26, q27, [sp, #416]
    ldp     q28, q29, [sp, #448]
    ldp     q30, q31, [sp, #480]
    add     sp, sp, #512

    /* Restore GPRs */
    ldp     x19, x20, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x29, x30, [sp], #16

    /* Return 0 = child */
    mov     x0, #0
    ret
