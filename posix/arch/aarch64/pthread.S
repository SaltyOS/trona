.section .text

.p2align 2
.global pthread_entry_trampoline
.type pthread_entry_trampoline, %function
pthread_entry_trampoline:
	ldp	x0, x1, [sp], #16
	b	pthread_trampoline_helper
.size pthread_entry_trampoline, . - pthread_entry_trampoline
