.intel_syntax noprefix
.section .text

.global trona_runtime_read_tp_raw
.type trona_runtime_read_tp_raw, @function
trona_runtime_read_tp_raw:
	mov	rax, qword ptr fs:[0]
	ret
.size trona_runtime_read_tp_raw, . - trona_runtime_read_tp_raw
