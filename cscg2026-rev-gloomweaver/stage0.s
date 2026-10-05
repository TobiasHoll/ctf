# Flag pointer is in %rdi, current state is in %rax.
# We can make bad comparisons if %rax is set.
# This checks the flag format (dach2026{...}).
# We don't check the '{' but that's good enough

xorl %ecx, %ecx
movl (%rdi), %esi
p0_0: cmpl $0x7b465443, %esi # (+2) CTF{ -> dach
setnz %cl
orl %ecx, %eax

movl 4(%rdi), %esi
p0_1: cmpl $0x73316874, %esi # (+2) th1s -> 2026
setnz %cl
orl %ecx, %eax

p0_2: pushq %rcx # (+0) -> pushq %rax
pushq %rdi
xorl %eax, %eax
movl $127, %ecx

repne scasb
subq (%rsp), %rdi
cmpq $(127 - 1 - 64), %rcx
setnz %cl

popq %rdi
p0_3: popq %rcx # (+0) -> popq %rax
orl %ecx, %eax

cmpb $0x7d, 0x3f(%rdi)
setnz %cl
orl %ecx, %eax

xorl %esi, %esi
movl $0x3e, %ecx
bit_test:
    btw $7, (%rdi, %rcx)
    setc %sil
    orl %esi, %eax
loop bit_test
