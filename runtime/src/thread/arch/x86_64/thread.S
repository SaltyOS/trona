.intel_syntax noprefix
.section .text

.global thread_entry_trampoline
.type thread_entry_trampoline, @function
thread_entry_trampoline:
	pop	rax
	pop	rdi
	pop	rdx
	mov	rsi, rax
	jmp	thread_entry_helper
.size thread_entry_trampoline, . - thread_entry_trampoline
