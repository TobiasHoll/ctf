#define __STDC_WANT_IEC_60559_BFP_EXT__
#define _GNU_SOURCE
#include <limits.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/wait.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "shared.h"

#define STACK_SIZE  0x1000
#define STACK_ALIGN 0x1000

_Alignas(STACK_ALIGN) char verifier_stack[STACK_SIZE] = {};
const struct clone_args verifier_clone_args = {
    .flags = CLONE_UNTRACED | CLONE_VM | CLONE_SYSVSEM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD,
    .stack = (unsigned long) verifier_stack,
    .stack_size = sizeof(verifier_stack),
};

unsigned long interrupt_frame[5] = {
    (unsigned long) implant,
    0x33, // cs
    0x502, // flags
           // As long as 0x100 (TF) is set, we can do whatever we want here.
           // We shouldn't rely on 0x400 (DF) since that'll be reset eventually and it's hard to predict when.
    (unsigned long) interrupt_frame,
    0x2b, // ss
};

__attribute__((naked, section(".fini")))
void actual_entry(void)
{
    __asm__ volatile (
        // We must restore rdi (main) and rsi (argc) later.
        "xchgq %rdi, %rbp\n"
        "movl %esi, %ebx\n"
        // syscall(SYS_clone3, &clone_args, sizeof(verifier_clone_args))
        "leaq verifier_clone_args(%rip), %rdi\n"
        "movl $88, %esi\n"
        "movl $0x1b3, %eax\n"
        "jmp 1f\n"
        ".global sa_restorer\n"
        "sa_restorer: mov $0xf, %eax\n"
        "1: syscall\n"
        // Only do our stuff in the == 0 case. Silently ignore errors.
        "testl %eax, %eax\n"
        "movl %ebx, %esi\n"
        "movq %rbp, %rdi\n"
        "jz verifier_thread\n"
        // Restore rdi, rsi, and rcx (init)
        "xorl %ecx, %ecx\n"
        "xorl %ebp, %ebp\n"
        // Jump back out
        "jmp *0x4ff4f4f4(%rip)\n"
    );
}
__attribute__((section(".fini"))) extern void (*sa_restorer)(void);
__attribute__((section(".fini"))) extern void handle_signal(int signo, siginfo_t *info, void *context);

extern void stage_1(long result, char *flag);
extern int main(int argc, char *argv[]);

__attribute__((noreturn, section(".fini")))
void verifier_thread(long main_fn, long argc, char **argv)
{
    if (argc != 2)
        goto no_patch;

    // md15 checks the flag with some simple LFSR before patching the code.
    // Here, we do the same thing.
    unsigned char hash = 101;
    for (unsigned i = 0; argv[1][i]; ++i)
        hash = ((hash << 6) + hash + (hash >> 6)) ^ argv[1][i];
    if (hash != 12)
        goto no_patch;

    struct kernel_sigaction act;
    act.sa_handler = (__sighandler_t) handle_signal;
    act.sa_flags = SA_NODEFER | SA_RESTORER | SA_SIGINFO;
    act.sa_mask = 0;
    __asm__ volatile (
        "leaq sa_restorer(%%rip), %%rcx\n"
        "movq %%rcx, %c[off](%[act])\n"
        :: [act]"r"(&act), [off]"i"(offsetof(struct sigaction, sa_restorer))
        : "rcx"
    );

    set_sigaction(SIGSEGV, &act, NULL);
    set_sigaction(SIGILL, &act, NULL);
    set_sigaction(SIGBUS, &act, NULL);
    set_sigaction(SIGTRAP, &act, NULL);

    __asm__ volatile (
        "xchgq %%rsp, 0x18(%[frame])\n"
        "iretq\n"
        :: [frame]"r"(interrupt_frame), "b"(get_tid()), "d"(main_fn + ((char *) stage_1 - (char *) main))
    );

no_patch:
    __asm__ volatile (".global hang_verifier\nhang_verifier:\n");
    futex_wait_bitset((void *) &verifier_clone_args.flags, verifier_clone_args.flags, 1u << 31);
    __builtin_unreachable();
}
