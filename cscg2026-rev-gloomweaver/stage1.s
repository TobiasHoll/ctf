# Flag pointer is in %rdi, current state is in %rax.
# We can make bad comparisons if %rax is set.
# We have verified the flag format (except '{').

.extern synchronizer
.macro sync wake_bits, wait_count
  call wake_wait
  .int (\wake_bits << 8)
  .byte (1 << \wait_count) - 1
.endm

# (pre-stage: Patch 5, 6)

pushq %rax
leaq 8(%rdi), %r12
p1_6: subq $64, (%rdi) # (+2 2f/ec) (%rdi) -> %rsp

movl $8, %ecx
xorl %eax, %eax
movq %rsp, %rdi
rep stosq

xorl %r10d, %r10d
movl $202, %r8d  # Keep SYS_futex around

p1_5: leaq s1_coeffs_fake(%rip), %rsi # (+3 disp32) s1_coeffs_fake -> s1_coeffs
p1_11d: movl $55, %ecx # (+0 b9 37/bf 40) -> movl $64, %edi

sync 1, 3 # [T1] Unpatch 5, 6; patch 2, 3, 4, 11d; fake-patch 1

.extern s1_loop_done
.extern s1_inner_loop_done

s1_outer:
    decl %ecx
    movl %ecx, %ebp # Vector index
    imul $55, %ecx, %ecx
p1_12d:
    leaq (%rsi, %rcx), %r13 # Matrix row for this

p1_10d:
    movl $55, %ecx

    xchg %rsi, %r14
    s1_inner:
        decl %ecx
        # Compute the offset coefficients first
p1_4:
        leaq s1_offset_u_fake(%rip), %rsi # (+3 disp32) s1_offset_u_fake -> s1_offset_u
        movzbq (%rsi, %rbp), %rax
p1_3:
        leaq s1_offset_v_fake(%rip), %rsi # (+3 disp32) s1_offset_v_fake -> s1_offset_v
        mulb (%rsi, %rcx)
t1_2:
        sync 2, 3 # [T2] Unpatch 3, patch 8 (first time only), patch i
p1_i:
        imul $1337, %rax, %rax # lambda * u[row] * v[col]
p1_9d:
        addb (%r13, %rcx), %al # Coefficient base byte
        mulb (%r12, %rcx) # Flag byte
        addb %al, (%rsp, %rbp)
t1_3:
        sync 4, 3 # [T3] Re-patch 3, patch 1 (first time only)
        orl %esi, s1_inner_loop_done(%rip)
        incl %ecx
p1_2:
    loopne s1_inner # (+0 e0/e2) loopne -> loop
    xchg %rsi, %r14

    movl %ebp, %ecx
    incl %ecx
p1_1:
loopne s1_outer # (+0 e0/e2) loopne -> loop
movl %r8d, s1_loop_done(%rip)

t1_4:
sync 0xf, 3 # [T4] Unpatch 1, 2, 4, and i; patch 0, 9d, 10d, and 12d

movq %rsp, %rdi
p1_0: leaq s1_result_fake(%rip), %rsi
p1_13d: movl $55, %ecx

p1_8: std # (+0 fd 66 f2 a7 / fc 66 f3 a6) std -> cld, repne cmpsd -> repe cmpsb
repne cmpsw
setnz %cl

sync 16, 2 # [T5] Patch 7 and 13d; unpatch 0 and 8

andq $0xff, %rcx
orq %rcx, 64(%rsp)

p1_7: addq $64, (%rdi) # (+ 2 07/c4) (%rdi) -> %rsp
popq %rax
