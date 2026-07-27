.intel_syntax noprefix
.section .text

.global rtld_syscall6_raw
.type rtld_syscall6_raw, @function
rtld_syscall6_raw:
	push	rbx
	mov	rbx, rdi
	mov	rax, rsi
	mov	rdi, rdx
	mov	rsi, rcx
	mov	rdx, r8
	mov	r10, r9
	mov	r8, [rsp + 16]
	mov	r9, [rsp + 24]
	syscall
	mov	[rbx + 0], rax
	mov	[rbx + 8], rdx
	pop	rbx
	ret
.size rtld_syscall6_raw, . - rtld_syscall6_raw
