.intel_syntax noprefix
.text

.globl kernel32_invoke_raw
kernel32_invoke_raw:
	push	rbx
	mov	rbx, rcx
	mov	rdi, rdx
	mov	rsi, r8
	mov	rdx, r9
	mov	r10, [rsp + 48]
	mov	r8, [rsp + 56]
	mov	r9, [rsp + 64]
	xor	eax, eax
	syscall
	mov	[rbx + 0], rax
	mov	[rbx + 8], rdx
	pop	rbx
	ret
