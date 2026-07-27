.text

.globl kernel32_invoke_raw
kernel32_invoke_raw:
	mov	x9, x0
	mov	x0, x1
	mov	x1, x2
	mov	x2, x3
	mov	x3, x4
	mov	x4, x5
	mov	x5, x6
	mov	x8, #0
	svc	#0
	stp	x0, x1, [x9]
	ret
