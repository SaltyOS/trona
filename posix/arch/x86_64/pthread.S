.intel_syntax noprefix
.section .text

.global pthread_entry_trampoline
.type pthread_entry_trampoline, @function
pthread_entry_trampoline:
	pop	rdi
	pop	rsi
	jmp	pthread_trampoline_helper
.size pthread_entry_trampoline, . - pthread_entry_trampoline
