#  0 0 REG_R8
#  1 1 REG_R9
#  2 2 REG_R10
#  3 3 REG_R11
#  4 4 REG_R12
#  5 5 REG_R13
#  6 6 REG_R14
#  7 7 REG_R15
#  8 8 REG_RDI
#  9 9 REG_RSI
# 10 a REG_RBP
# 11 b REG_RBX
# 12 c REG_RDX
# 13 d REG_RAX
# 14 e REG_RCX
# 15 f REG_RSP
# 16   REG_RIP
# 17   REG_EFL
# 18   REG_CSGSFS
# 19   REG_ERR
# 20   REG_TRAPNO
# 21   REG_OLDMASK
# 22   REG_CR2

# Wait masks must be += 8'd, not just incremented.
# That's a little unfortunate.
# Instead we do x ^= (x + 1), which in our case is equivalent.
leaq (t1_2 + 9 - stage_1)(%rdx), %rax # => t1_2 + 9
addq $(t1_4 - t1_2), %rax # => t1_4 + 9
.byte 0xed, 0x55, 0x81 # rax[48:40] += 0x81
xorl %ebp, %ebp

# Our "wake" is 1 << 3.
# TF should be set so grab it there (maybe someone thinks this is anti-debug?)
# We can use (without lock abuse)
#  r8:  60
#  r9:  61
#  r10: 62, 82
#  r12: c4, d4
#  r13: c5, d5
#  r14: 06, 16, d6
#  r15: 07, 17, 27, 37
#  rbp: 9a, ea
#  rcx: 0e, 1e
#  rsp: 1f, 2f, 3f
pushfq
pop %rcx
shrl $5, %ecx
andl $0x8, %ecx

# T2: 0x200
.byte 0xda, 0xb9, 0x22 # rbp[16:8] += 0x22

# Wait for T2 to patch p1_i
addq $(p1_i + 3 - stage_1), %rdx # p1_i + 3
.byte 0x9a # wait(rbp)
movq %rdx, %rax # 0x539 (1337) -> 0x503 (1283)
lock cmpxchgq %rbp, (%rax) # Reset rax
incw (%rdx) # -> 0x504 (1284)
.byte 0x0e # wake(rcx)

# T4: 0xf00
.byte 0xda, 0xb9, 0xa6 # rbp[16:8] += 0xa6

# Wait for T4 to unpatch p1_i
.byte 0x9a # wait(rbp)
movw $1337, (%rdx)
xorl %edx, %edx
.byte 0x0e # wake(rcx)

.byte 0x2a, 0x97, 0x80 # rbp[63:56] = 0x80
leave                  # (will trigger SIGBUS due to corrupted rbp/rsp)
ret                    # (decoy return)
