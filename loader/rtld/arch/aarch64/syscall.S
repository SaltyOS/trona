.section .text

.p2align 2
.global rtld_syscall6_raw
.type rtld_syscall6_raw, %function
rtld_syscall6_raw:
	mov	x9, x0
	mov	x8, x1
	mov	x0, x2
	mov	x1, x3
	mov	x2, x4
	mov	x3, x5
	mov	x4, x6
	mov	x5, x7
	svc	#0
	stp	x0, x1, [x9]
	ret
.size rtld_syscall6_raw, . - rtld_syscall6_raw
