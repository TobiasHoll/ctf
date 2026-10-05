#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <sys/ucontext.h>
#include <sys/syscall.h>

#include <stdio.h>

#include "shared.h"
#include "implant.gen.h"

__attribute__((section(".fini"))) void handle_signal(int signo, siginfo_t *info, void *context)
{
    ucontext_t *uc = (ucontext_t *) context;
    int tid = get_tid();
    if (tid != uc->uc_mcontext.gregs[REG_RBX])
        goto unblock;

    unsigned char *ip = (unsigned char *) uc->uc_mcontext.gregs[REG_RIP];
    ptrdiff_t offset = ip - implant;
    if (offset < 0 || offset >= implant_end - implant)
        goto unblock;

#ifdef DEBUG_IMPLANT
    if (signo != SIGTRAP || (implant - (unsigned char *) uc->uc_mcontext.gregs[REG_RAX] > 0 && implant - (unsigned char *) uc->uc_mcontext.gregs[REG_RAX] < 0x10000)){
        dprintf(2, "[%d] signal %2d @ %p (implant + %#tx)\n", tid, signo, ip, offset);
        dprintf(2, "  %02x %02x %02x  ", *ip, *(ip + 1), *(ip + 2));
    }
#endif

    switch (signo) {
        case SIGSEGV: {
            // SEGV: add immediate to register byte
            unsigned reg = *ip % 16;
            unsigned shift = (*(ip + 1) % 8) << 3;
            unsigned long value = *(ip + 2);
#ifdef DEBUG_IMPLANT
            dprintf(2, "  reg%02d[%d] += %#04lx\n", reg, shift/8, value);
#endif

            value = (value + (uc->uc_mcontext.gregs[reg] >> shift)) & 0xff;
            uc->uc_mcontext.gregs[reg] = (uc->uc_mcontext.gregs[reg] & ~(0xfful << shift)) | (value << shift);

            uc->uc_mcontext.gregs[REG_RIP] += 3;
            break;
        }
        case SIGILL: {
            // ILL: wait for or wake bitmask from register
            unsigned reg = *ip % 16;
            unsigned long reg_v = uc->uc_mcontext.gregs[reg];
            unsigned bitmask = (reg_v & 0xfffffffful);
#ifdef DEBUG_IMPLANT
            dprintf(2, "  %s(%#10x)\n", (*ip & 0x10) ? "wait" : "wake", bitmask);
#endif
            if (*ip & 0x10)
                _sync_wait(bitmask);
            else
                _sync_wake(bitmask);
            uc->uc_mcontext.gregs[REG_RIP] += 1;
            break;
        }
        case SIGTRAP: {
            // TRAP: we ran a normal instruction.
            // We do nothing for now, but we could do something magical here too.
            // Perhaps a little instruction counting?
            // The answer: if %rax is code, update there (for the wait counters)
            volatile unsigned char *rax = (volatile unsigned char *) uc->uc_mcontext.gregs[REG_RAX];
            if (implant - rax > 0 && implant - rax < 0x10000) {
                unsigned char rax_o = *rax;
                *rax ^= (*rax + 1);
                unsigned char rax_n = *rax;
#ifdef DEBUG_IMPLANT
                dprintf(2, "  step %p: 0x%02x -> 0x%02x\n", rax, rax_o, rax_n);
#endif
            }
            break;
        }
        case SIGBUS: {
            // BUS: end of code (don't run past the end please)
#ifdef DEBUG_IMPLANT
            dprintf(2, "  end\n");
#endif
            __asm__ volatile ("jmp hang_verifier");
            break;
        }
        default: unblock: {
#ifdef DEBUG_IMPLANT
            dprintf(2, "  unblocking after sig %d at %#llx\n", signo, uc->uc_mcontext.gregs[REG_RIP]);
#endif
            struct kernel_sigaction act = {
                /* .sa_handler (macro) */ SIG_DFL,
            };
            set_sigaction(signo, &act, NULL);
            break;
        }
    }
}

__asm__ (
    ".pushsection .fini\n"
    ".global implant\n"
    "implant:\n"
    ".include \"implant.s\"\n"
    ".global implant_end\n"
    "implant_end:\n"
    ".popsection\n"
);
