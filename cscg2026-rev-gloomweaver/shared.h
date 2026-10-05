#pragma once
#include <limits.h>
#include <linux/futex.h>
#include <stddef.h>
#include <sys/syscall.h>

// Glibc is a menace.
#ifdef _ASM_X86_SIGNAL_H
#undef _ASM_X86_SIGNAL_H
#endif
#pragma push_macro("sa_handler")
#undef sa_handler
#define sigaction kernel_sigaction
#define sigset_t kernel_sigset_t
#define sigaltstack kernel_sigaltstack
#define stack_t kernel_stack_t
#include <asm/signal.h>
#undef sigaction
#undef sigset_t
#undef sigaltstack
#undef stack_t
#pragma pop_macro("sa_handler")

__attribute__((always_inline))
static inline long futex_wake_bitset(void *uaddr, int waiters, unsigned bitmask)
{
    register long rax __asm__("rax") = SYS_futex;
    register long r10 __asm__("r10") = 0;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = bitmask;
    __asm__ volatile (
        "syscall\n"
        : "+a"(rax)
        : "D"(uaddr), "S"(FUTEX_WAKE_BITSET_PRIVATE), "d"(waiters), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11"
    );
    return rax;
}

__attribute__((always_inline))
static inline long futex_wait_bitset(void *uaddr, unsigned wait_while_value, unsigned bitmask)
{
    register long rax __asm__("rax") = SYS_futex;
    register long r10 __asm__("r10") = 0;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = bitmask;
    __asm__ volatile (
        "syscall\n"
        : "+a"(rax)
        : "D"(uaddr), "S"(FUTEX_WAIT_BITSET_PRIVATE), "d"(wait_while_value), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11"
    );
    return rax;
}

__attribute__((always_inline))
static inline long set_sigaction(int signo, struct kernel_sigaction *act, struct kernel_sigaction *oact)
{
    long nr = SYS_rt_sigaction;
    __asm__ volatile (
        "movl %[ssz], %%r10d\n"
        "syscall\n"
        : "+a"(nr) : "D"(signo), "S"(act), "d"(oact), [ssz]"i"(sizeof(kernel_sigset_t))
        : "rcx", "r10", "r11", "memory"
    );
    return nr;
}

__attribute__((always_inline))
static inline int get_tid(void) {
    long tid = SYS_gettid;
    __asm__ volatile ("syscall" : "+a"(tid) :: "rcx", "r11");
    return tid;
}


typedef volatile unsigned sync_t;

__attribute__((always_inline))
static inline void sync_step(sync_t *s, unsigned bitmask)
{
    unsigned current;
    for (unsigned previous = *s;;) {
        current = previous | bitmask;
        __asm__ volatile goto ("lock cmpxchgl %[r], (%[s]); jz %l[done]" : "+a"(previous) : [r]"r"(current), [s]"r"(s) :: done);
    }
done:
    futex_wake_bitset((void *) s, INT_MAX, current);
}

__attribute__((always_inline))
static inline void sync_wait_mask(volatile sync_t *s, unsigned bitmask, unsigned target, int consume)
{
    for (;;) {
        unsigned st;
        // Wait for a wakeup with this bitset
        for (;;) {
            st = *s;
            unsigned active = (st & bitmask);
            if (target ? (active != target) : !active)
                futex_wait_bitset((void *) s, st, bitmask);
            else
                break;
        }
        // We have a wakeup. Consume it atomically (or don't).
        if (!consume)
            break;

        unsigned next = 0;
        __asm__ volatile goto ("lock cmpxchg %[r], (%[s]); jz %l[consumed]" : "+a"(st) : [r]"r"(next), [s]"r"(s) :: consumed);
    }
consumed:
    return;
}


extern volatile sync_t synchronizer; // main.c

#define _sync_wait(bitmask) sync_wait_mask(&synchronizer, (bitmask), 0, 0)
#define _sync_wait_all(bitmask) sync_wait_mask(&synchronizer, (bitmask), (bitmask), 1)
#define _sync_wake(bitmask) sync_step(&synchronizer, (bitmask))

extern void sync_wait(unsigned bitmask); // main.c
extern void sync_wait_all(unsigned bitmask); // main.c
extern void sync_wake(unsigned bitmask); // main.c


extern const unsigned char implant[]; // implant.c
extern const unsigned char implant_end[]; // implant.c
