.section .text

.p2align 2
.global thread_entry_trampoline
.type thread_entry_trampoline, %function
thread_entry_trampoline:
	ldp	x1, x0, [sp], #16
	ldr	x2, [sp], #16
	b	thread_entry_helper
.size thread_entry_trampoline, . - thread_entry_trampoline
