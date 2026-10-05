#include <err.h>
#include <linux/ptrace.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "shared.h"
__asm__ (".include \"flag.gen.s\"\n");

__attribute__((noinline, no_stack_protector)) void sync_wait(unsigned bitmask) { _sync_wait(bitmask); }
__attribute__((noinline, no_stack_protector)) void sync_wait_all(unsigned bitmask) { _sync_wait_all(bitmask); }
__attribute__((noinline, no_stack_protector)) void sync_wake(unsigned bitmask) { _sync_wake(bitmask); }

#define THREAD_COUNT 4
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

_Static_assert(THREAD_COUNT <= sizeof(unsigned) * 8, "Too many threads");

sync_t synchronizer = 0;
volatile unsigned s1_loop_done = 0;
volatile unsigned s1_inner_loop_done = 0;

#define S0_READY_1 0x40
#define S0_READY_2 0x80

#define PATCH_ADDR(name) ({ extern char name[]; (char *) name - (char *) main; })
#define PATCH(type, name, offset) *(type *) (base + PATCH_ADDR(name) + offset)

#define DELTA_MARK 0x4fccf400u
#define DELTA(index, to, from) ({ extern const char from[], to[]; DELTA_MARK | (index); })

#define DELTA_COEFFS DELTA(0, s1_coeffs,   s1_coeffs_fake)
#define DELTA_U      DELTA(1, s1_offset_u, s1_offset_u_fake)
#define DELTA_V      DELTA(2, s1_offset_v, s1_offset_v_fake)
#define DELTA_RESULT DELTA(3, s1_result,   s1_result_fake)

int main(int argc, char *argv[]);

// TX table
//     T1  T2  T3  T4  T5
// t0   -   -   2   2   1
// t1   2   0   1   0   -
// t2   1   2   -   -   0
// t3   0   1   0   1   -
//
// #    3   3   3   3   2
// i    -   3   -   3   -

void thread_0(unsigned char *base) {
    sync_wait(S0_READY_1);
        PATCH(unsigned, p0_0, 2) -= 0x12e2f2df;
    sync_wake(1 << 0);
    // Pre-stage 1: patch 5
    sync_wait(S0_READY_2);
        PATCH(unsigned, p0_0, 2) += 0x12e2f2df;
        PATCH(unsigned, p1_5, 3) += DELTA_COEFFS;
    sync_wake(1 << 0);

    // T1: (no wait)

    // T2: (no wait)

    // T3: Patch 1
    sync_wait(0x50400);
        PATCH(unsigned char, p1_1, 2) += 1;
    sync_wake(1 << 2);

    // T4: Unpatch 4
    sync_wait(0x8f900);
        extern const char s1_offset_u_fake[];
        extern const char s1_offset_u[];
        PATCH(unsigned, p1_4, 3) -= DELTA_U;
    sync_wake(1 << 2);

    // T5: Unpatch 0, patch 13d
    sync_wait(0xaf000);
        extern const char s1_result_fake[];
        extern const char s1_result[];
        PATCH(unsigned, p1_0, 3) -= DELTA_RESULT;
        PATCH(unsigned char, p1_13d, 1) = 128;
    sync_wake(1 << 1);
}

void thread_1(unsigned char *base) {
    sync_wait(S0_READY_1);
        PATCH(unsigned, p0_1, 2) -= 0x3cff3842;
    sync_wake(1 << 1);
    // Pre-stage 1: patch 6
    sync_wait(S0_READY_2);
        PATCH(unsigned, p0_1, 2) += 0x3cff3842;
        PATCH(unsigned char, p1_6, 2) = 0xec;
    sync_wake(1 << 1);

    // T1: Unpatch 5, patch 2, 11d
    sync_wait(0xa3300);
        PATCH(unsigned char, p1_2, 0) = 0xe2;
        PATCH(unsigned, p1_5, 3) -= DELTA_COEFFS;
        PATCH(unsigned short, p1_11d, 0) = 0x40bf;
    sync_wake(1 << 2);

    // T2: Unpatch 3
    // T3: (nothing)
    for (;;) {
        sync_wait(0xc9a00);
            if (s1_loop_done)
                break; // This is the 0xf0 case
            PATCH(unsigned, p1_3, 3) -= DELTA_V;
        sync_wake(1 << 0);

        sync_wait(0x17500); // T3
            // Restore T2 sync bitmask to two threads (the implant does not loop, and neither does T1).
            PATCH(unsigned char, t1_2, 9) = 3;
        sync_wake(1 << 1);
    }

    // T4: Patch 0, 10d, 12d
    // (wait in the loop)
        PATCH(unsigned, p1_0, 3) += DELTA_RESULT;
        PATCH(unsigned, p1_10d, 0) = 0xa0eba97c;
        PATCH(unsigned short, p1_12d, 2) = 0x7124;
    sync_wake(1 << 0);

    // T5: (no wait)
}

void thread_2(unsigned char *base) {
    sync_wait(S0_READY_1);
        PATCH(unsigned char, p0_2, 0) -= 1;
    sync_wake(1 << 2);
    sync_wait(S0_READY_2);
        PATCH(unsigned char, p0_3, 0) += 1;
        // Pre-stage 1: nothing
    sync_wake(1 << 2);

    // T1: Unpatch 6, patch 4, fake-patch 1
    sync_wait(0xff900);
        PATCH(unsigned, p1_4, 3) += DELTA_U;
        PATCH(unsigned char, p1_6, 2) = 0x2f;
        PATCH(unsigned char, p1_1, 2) += 1;
    sync_wake(1 << 1);

    // T2: Patch 8
    sync_wait(0xd4200);
        PATCH(unsigned, p1_8, 0) -= 0xff0001;
    sync_wake(1 << 2);

    // T3: (no wait)

    // T4: (no wait)

    // T5: Patch 7, unpatch 8
    sync_wait(0xad000);
        PATCH(unsigned char, p1_7, 2) = 0xc4;
        PATCH(unsigned short, p1_8, 0) = 0x67fd;
    sync_wake(1 << 0);
}

void thread_3(unsigned char *base) {
    sync_wait(S0_READY_1);
        PATCH(unsigned char, p0_3, 0) -= 1;
    sync_wake(1 << 3);
    sync_wait(S0_READY_2);
        PATCH(unsigned char, p0_3, 0) += 1;
        // Pre-stage 1: nothing
    sync_wake(1 << 3);

    // T1 and T3: Patch 3
    // T2: (nothing)
    for (;;) {
        sync_wait(0xb8500);
            PATCH(unsigned, p1_3, 3) += DELTA_V;
        sync_wake(1 << 0);

        sync_wait(0xca200); // (T2)
            if (s1_loop_done)
                break;
            // Restore T3 sync bitmask to two threads on the second time around (the implant does not loop, and neither does T1).
            if (s1_inner_loop_done)
                PATCH(unsigned char, t1_3, 9) = 3;
        sync_wake(1 << 1);
    }

    // T4: Unpatch 1 and 2; patch 9d
    // (wait in the loop)
        PATCH(unsigned char, p1_1, 2) -= 1;
        PATCH(unsigned char, p1_2, 0) -= 2;
        PATCH(unsigned char, p1_9d, 0) = 0x66;
    sync_wake(1 << 1);
}

__attribute__((noinline))
long stage_0(long result, char *flag)
{
    // Stage 0 just checks the flag format
    // This tells people how this stuff is supposed to work
    __asm__ volatile (
        ".include \"stage0.s\""
        : "+a"(result), "+D"(flag) :: "cc", "memory", "rsi", "rcx"
    );
    return result;
}

__asm__ (".include \"stage1-sync.s\"\n");

__attribute__((noinline))
long stage_1(long result, char *flag)
{
    // Now do the "proper" checks
    // This is a bit more complicated.
    __asm__ volatile (
        ".include \"stage1.s\""
        : "+a"(result), "+D"(flag) :: "cc", "memory", "rsi", "rdx", "rbx", "rcx", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14"
    );
    return result;
}

int main(int argc, char *argv[])
{
    // This is what tooling thinks is the "main" function.

    // We create multiple threads here.
    // That gives a 'reason' for the clone3 call earlier.

    // Those threads patch around in the code here.
    // That gives us a reason to have it be RWX.

    // (Ignore the hidden thread :D)

    if (argc != 2)
        errx(EXIT_FAILURE, "usage: %s flag", argv[0]);

    char *flag = argv[1];

    pthread_t threads[THREAD_COUNT];
    pthread_attr_t detached;
    pthread_attr_init(&detached);
    pthread_attr_setdetachstate(&detached, PTHREAD_CREATE_DETACHED);

#define CREATE_THREAD(index) pthread_create(&threads[index], &detached, (void *(*)(void *)) thread_##index, (void *) main)
    CREATE_THREAD(0);
    CREATE_THREAD(1);
    CREATE_THREAD(2);
    CREATE_THREAD(3);

    long result = SYS_ptrace;
    __asm__ volatile ("syscall" : "+a"(result) : "D"(PTRACE_TRACEME) : "rcx", "r11");

    // NB: Order: if a wait hits after the corresponding wake, we're screwed.
    usleep(500000);

    long second_try = SYS_ptrace;
    __asm__ volatile ("syscall; incq %%rax" : "+a"(second_try) : "D"(PTRACE_TRACEME) : "rcx", "r11");
    result |= second_try;

    sync_wake(S0_READY_1);
    sync_wait_all((1u << THREAD_COUNT) - 1);
    result |= stage_0(result, flag);
    sync_wake(S0_READY_2);
    sync_wait_all((1u << THREAD_COUNT) - 1);
    if (!result)
        result |= stage_1(result, flag);

    puts(result ? ":(" : ":)");
    return EXIT_SUCCESS;
}
