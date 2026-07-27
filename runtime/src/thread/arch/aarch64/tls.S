.section .text

.p2align 2
.global trona_runtime_read_tp_raw
.type trona_runtime_read_tp_raw, %function
trona_runtime_read_tp_raw:
	mrs	x0, TPIDR_EL0
	ret
.size trona_runtime_read_tp_raw, . - trona_runtime_read_tp_raw
