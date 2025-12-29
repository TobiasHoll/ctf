#pragma once

#include "utils.h"

#include <array>
#include <cstdint>
#include <span>
#include <wmmintrin.h>

namespace aesni {
    struct alignas(16) aes_block : public std::array<uint8_t, 16> {};
    struct alignas(16) aes256_keys : public std::array<uint8_t, 15 * 16>
    {
        aes_block decrypt_ecb(const aes_block &block) const
        {
            __m128i state = _mm_load_si128(reinterpret_cast<const __m128i *>(block.data()));
            const __m128i *keys = reinterpret_cast<const __m128i *>(this->data());

            state = _mm_xor_si128(state, keys[14]);
            state = _mm_aesdec_si128(state, keys[13]);
            state = _mm_aesdec_si128(state, keys[12]);
            state = _mm_aesdec_si128(state, keys[11]);
            state = _mm_aesdec_si128(state, keys[10]);
            state = _mm_aesdec_si128(state, keys[9]);
            state = _mm_aesdec_si128(state, keys[8]);
            state = _mm_aesdec_si128(state, keys[7]);
            state = _mm_aesdec_si128(state, keys[6]);
            state = _mm_aesdec_si128(state, keys[5]);
            state = _mm_aesdec_si128(state, keys[4]);
            state = _mm_aesdec_si128(state, keys[3]);
            state = _mm_aesdec_si128(state, keys[2]);
            state = _mm_aesdec_si128(state, keys[1]);
            state = _mm_aesdeclast_si128(state, keys[0]);

            aes_block result = {};
            _mm_store_si128(reinterpret_cast<__m128i *>(result.data()), state);
            return result;
        }

        std::span<const uint8_t, 16> round(size_t index) const
        {
            return std::span<const uint8_t, 16> { &this->data()[index * 16], 16 };
        }
    };
    struct alignas(32) aes_key : public std::array<uint8_t, 32>
    {
        aes256_keys for_encryption() const
        {
            aes256_keys key_schedule = {};

            const __m128i *input = reinterpret_cast<const __m128i *>(this->data());
            __m128i *output = reinterpret_cast<__m128i *>(key_schedule.data());

            __m128i state0 = input[0];
            __m128i state1 = input[1];

            output[0] = state0;
            output[1] = state1;

#define aes256_key_schedule_round_a(round, rcon) do { \
            state0 = _mm_xor_si128(state0, _mm_slli_si128(state0, 4)); \
            state0 = _mm_xor_si128(state0, _mm_slli_si128(state0, 8)); \
            output[round] = state0 = _mm_xor_si128(state0, _mm_shuffle_epi32( \
                _mm_aeskeygenassist_si128(state1, rcon), \
                0xff \
            )); \
        } while (0)
#define aes256_key_schedule_round_b(round) do { \
            state1 = _mm_xor_si128(state1, _mm_slli_si128(state1, 4)); \
            state1 = _mm_xor_si128(state1, _mm_slli_si128(state1, 8)); \
            output[round] = state1 = _mm_xor_si128(state1, _mm_shuffle_epi32( \
                _mm_aeskeygenassist_si128(state0, 0), \
                0xaa \
            )); \
        } while (0)

            aes256_key_schedule_round_a(2, 0x01);
            aes256_key_schedule_round_b(3);
            aes256_key_schedule_round_a(4, 0x02);
            aes256_key_schedule_round_b(5);
            aes256_key_schedule_round_a(6, 0x04);
            aes256_key_schedule_round_b(7);
            aes256_key_schedule_round_a(8, 0x08);
            aes256_key_schedule_round_b(9);
            aes256_key_schedule_round_a(10, 0x10);
            aes256_key_schedule_round_b(11);
            aes256_key_schedule_round_a(12, 0x20);
            aes256_key_schedule_round_b(13);
            aes256_key_schedule_round_a(14, 0x40);

#undef aes256_key_schedule_round_a
#undef aes256_key_schedule_round_b

            return key_schedule;
        }

        aes256_keys for_decryption() const
        {
            auto inverse = for_encryption();
            __m128i *keys = reinterpret_cast<__m128i *>(inverse.data());

            for (size_t round = 1; round < 14; ++round)
                keys[round] = _mm_aesimc_si128(keys[round]);

            return inverse;
        }
    };

#if defined(_HXP_AES_SELFTEST)
    inline void selftest_failed(void)
    {
        utils::exit_with_message("aes-ni selftest failed");
    }

    inline void selftest(void)
    {
        // FIPS 197 test vector.
        aes_key key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

        auto schedule = key.for_encryption();
        const std::array<uint8_t, 16> expected_round_2_key = {
            0xa5, 0x73, 0xc2, 0x9f, 0xa1, 0x76, 0xc4, 0x98, 0xa9, 0x7f, 0xce, 0x93, 0xa5, 0x72, 0xc0, 0x9c
        };
        const std::array<uint8_t, 16> expected_round_14_key = {
            0x24, 0xfc, 0x79, 0xcc, 0xbf, 0x09, 0x79, 0xe9, 0x37, 0x1a, 0xc2, 0x3c, 0x6d, 0x68, 0xde, 0x36
        };

        auto cipher = key.for_decryption();
        const aes_block expected_plaintext = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };

        aes_block ciphertext = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
        aes_block plaintext = cipher.decrypt_ecb(ciphertext);

        for (size_t i = 0; i < 16; ++i) {
            utils::assert(expected_round_2_key[i] == schedule.round(2)[i], selftest_failed);
            utils::assert(expected_round_14_key[i] == schedule.round(14)[i], selftest_failed);
            utils::assert(expected_plaintext[i] == plaintext[i], selftest_failed);
        }
    }
#endif
}

