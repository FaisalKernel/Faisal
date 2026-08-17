.section .rodata
msg:
	.ascii "launcher-probe-ok\n"
.set msg_len, .-msg

.section .text
.global _start
.type _start,@function
_start:
	mov $1, %rax
	mov $1, %rdi
	lea msg(%rip), %rsi
	mov $msg_len, %rdx
	syscall
	mov $60, %rax
	xor %rdi, %rdi
	syscall
	hlt
.size _start, .-_start
