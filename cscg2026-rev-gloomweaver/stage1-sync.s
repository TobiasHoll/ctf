wake_wait:
  # r8 is always SYS_futex, r10 is always zero.
  # Clobbers rdi, rdx, r9, r11
  pushq %rax
  pushq %rbp
  pushq %rcx
  pushq %rsi
  movq 0x20(%rsp), %rbp
  addq $5, 0x20(%rsp)
    leaq synchronizer(%rip), %rdi # &synchronizer

    # Wake the threads
    movl (%rdi), %eax # existing bitmask
    wake_retry:
      movl (%rbp), %r9d # signal bitmask
      orl %eax, %r9d # combined (new) bitmask
      lock cmpxchgl %r9d, (%rdi) # do the store
      jnz wake_retry

    # futex_wake_bitset: rdi, r10, r9 already set correctly; r8 is ignored
    movl %r8d, %eax  # SYS_futex
    leal (0x8a - 0xca)(%eax), %esi # FUTEX_WAKE_BITSET_PRIVATE
    movl %esi, %edx  # max. waiters
    syscall

    # Now wait for all the expected responses
    movzbq 4(%rbp), %r9 # waiting for this bitmask
    wait_retry:
      movl (%rdi), %edx
      cmpb %dl, 4(%rbp)
      je wait_done
      # futex_wait_bitset: rdi, rdx, r10, r9 already set correctly; r8 is ignored
      movl %r8d, %eax # SYS_futex
      leal (0x89 - 0xca)(%eax), %esi # FUTEX_WAIT_BITSET_PRIVATE
      syscall
      jmp wait_retry

    # We have a bitmask match, consume it
    wait_done:
      movl %edx, %eax
      xorl %edx, %edx
      lock cmpxchgl %edx, (%rdi)
      jnz wait_retry

  popq %rsi
  popq %rcx
  popq %rbp
  popq %rax
  ret
