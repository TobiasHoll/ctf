#pragma once
#include "hash.h"

#include <immintrin.h>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

namespace payload {
    constexpr static size_t total_checks = 1024;
    constexpr static size_t valid_checks = 64;

    consteval std::array<uint8_t, 32> bit_mask_for(size_t check_id)
    {
        // Pick either 1 or 2 bits per byte, but two bits per byte is only allowed up to
        // 18 times (then, we have at most 64 bits in the bitmask even if 0xff replaces
        // single-bit bytes twice).
        uint64_t state = (0x70786800ul << 32) | check_id;
        for (size_t i = 0; i < 64; ++i)
            state = hash::xorshift64(state);

        std::array<uint8_t, 32> raw_bytes = {};
        size_t two_bits = 0;
        while (two_bits < 18) {
            state = hash::xorshift64(state);
            size_t byte = state & 0x1f;
            size_t bit1 = (state >> 5) & 0x7;
            size_t bit2 = (state >> 8) & 0x7;
            if (bit1 == bit2 || raw_bytes[byte])
                continue;
            raw_bytes[byte] = (1 << bit1) | (1 << bit2);
            ++two_bits;
        }

        for (size_t byte = 0; byte < 32; ++byte) {
            if (raw_bytes[byte])
                continue;
            state = hash::xorshift64(state);
            raw_bytes[byte] = 1 << (state & 0x7);
        }

        return raw_bytes;
    }

    consteval uint64_t partial_bit_mask_for(size_t check_id, size_t qword_index)
    {
        const auto mask = bit_mask_for(check_id);
        std::array<uint8_t, 8> section = {
            mask[qword_index * 8 + 0],
            mask[qword_index * 8 + 1],
            mask[qword_index * 8 + 2],
            mask[qword_index * 8 + 3],
            mask[qword_index * 8 + 4],
            mask[qword_index * 8 + 5],
            mask[qword_index * 8 + 6],
            mask[qword_index * 8 + 7],
        };
        return std::bit_cast<uint64_t>(section);
    }

    consteval uint64_t extra_qword(size_t check_id, size_t index)
    {
        uint64_t state = (0x70786801ul << 32) | check_id;
        for (size_t i = 0; i < 64 + index; ++i)
            state = hash::xorshift64(state);
        return state;
    }

    consteval uint64_t expected(size_t check_id)
    {
        switch (check_id) {
            case 527: return 10814324114ul;
            case 454: return 25537060346ul;
            case 113: return 677439217ul;
            case 397: return 53641472618ul;
            case 427: return 16427528599ul;
            case 629: return 29053292762ul;
            case 312: return 41438690912ul;
            case 176: return 55487231234ul;
            case 373: return 3248596369ul;
            case 334: return 4580422241ul;
            case 939: return 35747691662ul;
            case 354: return 32962551067ul;
            case 554: return 59238320185ul;
            case 167: return 25658303326ul;
            case 780: return 58443110257ul;
            case 757: return 49883052935ul;
            case 999: return 13811985020ul;
            case 1015: return 39167330146ul;
            case 286: return 30706889581ul;
            case 313: return 11988452204ul;
            case 172: return 23940394387ul;
            case 316: return 32244852528ul;
            case 333: return 29707538155ul;
            case 147: return 54229119006ul;
            case 693: return 61129482888ul;
            case 42: return 56251971322ul;
            case 419: return 32803545661ul;
            case 349: return 43925055489ul;
            case 240: return 24629891617ul;
            case 226: return 18801576453ul;
            case 767: return 7719568380ul;
            case 230: return 17943038778ul;
            case 267: return 68878049429ul;
            case 691: return 11583114202ul;
            case 918: return 2690802285ul;
            case 481: return 61712329762ul;
            case 256: return 39458785336ul;
            case 560: return 40878924820ul;
            case 916: return 24660702826ul;
            case 266: return 36432383475ul;
            case 677: return 45799432191ul;
            case 186: return 24064963024ul;
            case 818: return 46658446686ul;
            case 500: return 26463534286ul;
            case 553: return 66571531477ul;
            case 737: return 43227359709ul;
            case 33: return 18067215317ul;
            case 275: return 49346145840ul;
            case 793: return 27591054080ul;
            case 1004: return 3319719463ul;
            case 613: return 41186568794ul;
            case 450: return 47790378557ul;
            case 781: return 8517677387ul;
            case 108: return 32875576706ul;
            case 252: return 66476842424ul;
            case 741: return 16963430168ul;
            case 522: return 1144271476ul;
            case 938: return 19238138396ul;
            case 852: return 20872581175ul;
            case 111: return 17284129435ul;
            case 699: return 66233868703ul;
            case 567: return 28779966736ul;
            case 170: return 63031545817ul;
            case 639: return 14668600107ul;
            default:
                return extra_qword(check_id, 0x100) & 0xf'ffff'fffful;
        }
    }

    // Returns success in the high 32 bits and the number of steps for the PRNG in the low 32 bits.
    // This should return distinct values on success and failure, though there may be
    // multiple failure paths. Try to keep this constant-time.
    // Also, do _not_ touch the stack in here, or make calls. That will break the rseq abort logic.
    // You can rely on the SysV ABI redzone though.
    template <size_t CheckId>
    [[gnu::naked, gnu::noinline, gnu::no_instrument_function]]
    static uint64_t check(const uint8_t *flag_bytes, unsigned index)
    {
        __asm__ volatile (
            // Sadly, we can't use v constraints below (they result in RIP-relative addressing)
            // So, initialize the data here.
            // For ymm1, I was hoping for a "simple" vmovdqa-load-from-memory here.
            // But for reasons(TM) we decided to make this memory XOM, so no reading allowed.
            "movabs %[m0], %%rax\n"
            "movabs %[m1], %%rcx\n"
            "vmovq %%rax, %%xmm0\n"
            "vmovq %%rcx, %%xmm1\n"
            "vpunpcklqdq %%xmm0, %%xmm1, %%xmm1\n"
            "movabs %[m2], %%rax\n"
            "movabs %[m3], %%rcx\n"
            "vmovq %%rax, %%xmm0\n"
            "vmovq %%rcx, %%xmm7\n"
            "vpunpcklqdq %%xmm0, %%xmm7, %%xmm0\n"
            "vinserti128 $1, %%xmm0, %%ymm1, %%ymm1\n"

            // ymm0 (the mask modification ff 00 ... ff 00 ...)
            "movl $0xff, %%eax\n"
            "vmovq %%rax, %%xmm0\n"
            "vinserti128 $1, %%xmm0, %%ymm0, %%ymm0\n"

            // Depending on the index and the check ID, do something different here.
            // In the end, all bits of that will need to have been checked.
            // We take bytes (index % 16) and (index % 16) + 16 from the flag.
            // From the ID, we select an additional random bitmask on the rest of
            // the flag, so we end up with exactly 64 bits in the bitmask.
            // This means the random bitmask should have 48 / 30 == 1.6 bits per flag byte
            // set (in such a way that even if we overwrite two bytes with 0xff, the total
            // number of bits in the mask is still <= 64).

            "andl $0xf, %%esi\n"
            "leaq (%%rsi, %%rsi, 4), %%rsi\n"
            "leaq (15 * 5 + 5)(%%rip), %%rax\n"
            "subq %%rsi, %%rax\n" // 3 bytes
            "jmp *%%rax\n" // 2 bytes
            ".rept 15\n"
            "vpslldq $1, %%ymm0, %%ymm0\n"
            ".endr\n"
            "vpor %%ymm0, %%ymm1, %%ymm1\n"
            "vmovdqa (%%rdi), %%ymm0\n"
            "vpand %%ymm1, %%ymm0, %%ymm0\n"

            // Now that it's all nicely masked, pack it into 64 bits for maths foo
            ".macro packqword index\n"
            "  vextracti128 $(\\index / 2), %%ymm1, %%xmm7\n"
            "  vpextrq $(\\index %% 2), %%xmm7, %%rsi\n"
            "  vextracti128 $(\\index / 2), %%ymm0, %%xmm7\n"
            "  vpextrq $(\\index %% 2), %%xmm7, %%rax\n"
            "  .ifeq \\index\n"
            "    pextq %%rsi, %%rax, %%rdi\n"
            "  .else\n"
            "    pextq %%rsi, %%rax, %%rax\n"
            "    popcnt %%rsi, %%rcx\n"
            "    shlq %%cl, %%rdi\n"
            "    orq %%rax, %%rdi\n"
            "  .endif\n"
            ".endm\n"
            "packqword 0\n"
            "packqword 1\n"
            "packqword 2\n"
            "packqword 3\n"
            ".purgem packqword\n"

            // Split into individual bytes and compute stuff with it.
            "movq %%rdi, -8(%%rsp)\n"
            "xorl %%edi, %%edi\n"

            ".macro mangle index m a toggle\n"
            "  .ifne \\index\n"
            "    rolq $4, %%rdi\n"
            "  .endif\n"
            "  movb (\\index - 8)(%%rsp), %%al\n"
            "  movl \\m, %%esi\n"
            "  imulb %%sil\n"
            "  .ifeq (\\toggle & 1)\n"
            "    addl \\a, %%eax\n"
            "  .else\n"
            "    xorl \\a, %%eax\n"
            "  .endif\n"
            "  movzbl %%al, %%eax\n"
            "  .ifeq (\\toggle & 2)\n"
            "    addq %%rax, %%rdi\n"
            "  .else\n"
            "    xorq %%rax, %%rdi\n"
            "  .endif\n"
            ".endm\n"
            ".macro mangle_from_c index const\n"
            "  mangle \\index, $((\\const & 0xfe) + 1), $((\\const >> 8) & 0xff), (\\const >> 16)\n"
            ".endm\n"
            "mangle_from_c 0, %c[c0]\n"
            "mangle_from_c 1, %c[c1]\n"
            "mangle_from_c 2, %c[c2]\n"
            "mangle_from_c 3, %c[c3]\n"
            "mangle_from_c 4, %c[c4]\n"
            "mangle_from_c 5, %c[c5]\n"
            "mangle_from_c 6, %c[c6]\n"
            "mangle_from_c 7, %c[c7]\n"
            ".purgem mangle_from_c\n"
            ".purgem mangle\n"

            // rax: [ success ] [ prng rounds ]
            "movabs %[expected], %%rax\n"
#if defined(_HXP_DEBUG_IDS)
            "movq %%rdi, %%rdx\n"
#endif
            "subq %%rdi, %%rax\n"
            "movq %%rax, %%rdi\n"
            "shrq $32, %%rdi\n"
            "orl %%edi, %%eax\n"
            "shlq $32, %%rax\n"
            "xorq %[cr], %%rax\n"
            "ret\n"
            :: [id]"i"(CheckId),
               [m0]"i"(partial_bit_mask_for(CheckId, 0)),
               [m1]"i"(partial_bit_mask_for(CheckId, 1)),
               [m2]"i"(partial_bit_mask_for(CheckId, 2)),
               [m3]"i"(partial_bit_mask_for(CheckId, 3)),
               [c0]"i"(extra_qword(CheckId, 0)),
               [c1]"i"(extra_qword(CheckId, 1)),
               [c2]"i"(extra_qword(CheckId, 2)),
               [c3]"i"(extra_qword(CheckId, 3)),
               [c4]"i"(extra_qword(CheckId, 4)),
               [c5]"i"(extra_qword(CheckId, 5)),
               [c6]"i"(extra_qword(CheckId, 6)),
               [c7]"i"(extra_qword(CheckId, 7)),
               [cr]"i"(extra_qword(CheckId, 0xc0) & 0xfff), // Tweak the constant until unique
               [expected]"i"(expected(CheckId))
            : "rax", "rcx", "rdi", "rsi", "ymm0", "ymm1", "ymm7", "memory"
        );
    }

    using check_t = uint64_t (*)(const uint8_t *, unsigned);

#if defined(MAIN)
#define repeat_1(f, n) f(n)
#define repeat_4(f, n) repeat_1(f, n) repeat_1(f, n + 1) repeat_1(f, n + 2) repeat_1(f, n + 3)
#define repeat_16(f, n) repeat_4(f, n) repeat_4(f, n + 4) repeat_4(f, n + 8) repeat_4(f, n + 12)
#define repeat_64(f, n) repeat_16(f, n) repeat_16(f, n + 16) repeat_16(f, n + 32) repeat_16(f, n + 48)
#define repeat_256(f, n) repeat_64(f, n) repeat_64(f, n + 64) repeat_64(f, n + 128) repeat_64(f, n + 192)
#define repeat_1024(f, n) repeat_256(f, n) repeat_256(f, n + 256) repeat_256(f, n + 512) \
                          repeat_256(f, n + 768)

#define list_check_in_array(n) &check<n>,
    static const std::array<check_t, total_checks> checks = {
        repeat_1024(list_check_in_array, 0)
    };
#endif
}
