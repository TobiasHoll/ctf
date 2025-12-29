#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <source_location>

#include "hash.h"
#include "utils.h"

#if defined(_HXP_DEBUG)
#pragma GCC warning "_HXP_DEBUG is enabled!"
#endif

namespace strings {

    // Forward declarations as needed
    namespace gen {
        template <size_t Size>
        struct debug_string;
    }

    // A string-ish type that can only be created via "..."_debug.
    // This ensures that we don't have them around in the final binary once we disable debugging.
    class debug_only {
    public:
        constexpr operator const char *() const
        {
            return data;
        }

    private:
        constexpr debug_only(const char *data) : data(data) {}
        template <size_t Size> friend struct gen::debug_string;
        const char *data;
    };

    namespace gen {
        constexpr static inline void xor_buffers(char *dst, const char *src1, const char *src2,
                                                 size_t size)
        {
            while (size--)
                *dst++ = *src1++ ^ *src2++;
        }

        template <size_t Size>
        constexpr static inline auto xor_(std::array<char, Size> a, std::array<char, Size> b)
        {
            std::array<char, Size> result;
            for (size_t i = 0; i < Size; ++i)
                result[i] = a[i] ^ b[i];
            return result;
        }

        template <size_t Size>
        consteval static std::array<char, Size> generate_key(uint64_t seed)
        {
            std::array<char, Size> key;
            for (size_t index = 0; index < Size; index += 8) {
                seed = hash::xorshift64(seed);
                for (size_t byte = 0; byte < 8 && index + byte < Size; ++byte)
                    key[index + byte] = static_cast<char>((seed >> (8 * byte)) & 0xff);
            }
            return key;
        }

        template <size_t Size>
        struct wrapped_string {
            std::array<char, Size> key;
            std::array<char, Size> ciphertext;
            static_assert(sizeof(std::array<char, Size>) == Size, "std::array is weirdly sized");

            [[gnu::always_inline]] operator const char *() const
            {
                std::array<char, Size> *buffer = reinterpret_cast<std::array<char, Size> *>(
                    __builtin_alloca(Size)
                );
                // Optimization barrier: Don't assume anything about the key and ciphertext, i.e.,
                // don't precompute the actual plaintext.
                __asm__ volatile ( "" :: "rm"(key.data()), "rm"(ciphertext.data()) : "memory" );

                *buffer = xor_(key, ciphertext);

                // Optimization barrier: No, the plaintext buffer is not actually empty either.
                __asm__ volatile ( "" :: "rm"(buffer) : "memory" );
        
                // ... Convince the compiler to actually do something with this.
                if ((*buffer)[Size - 1] != '\0')
                    __builtin_trap();

                return buffer->data();
            }
        };

        // Encrypts the string. This is somewhat complex since it uses source_location to derive a key.
        template <size_t Size>
        struct string_wrapper {
            consteval string_wrapper(const char (&chars)[Size])
            {
                for (size_t index = 0; index < Size; ++index)
                    contents[index] = chars[index];
            }

            consteval static inline auto get_key_from_location(
                const std::source_location location = std::source_location::current()
            )
            {
                return gen::generate_key<Size>(hash::hash_location(location));
            }

            [[gnu::always_inline]] constexpr inline auto operator()(
                const std::array<char, Size> key = get_key_from_location()
            ) const
            {
                std::array<char, Size> ciphertext = xor_(contents, key);
                return wrapped_string { key, ciphertext };
            }

            std::array<char, Size> contents;
        };

        // Hashes the incoming string immediately, at compile time
        template <size_t Size>
        struct string_hasher {
            consteval string_hasher(const char (&chars)[Size])
            {
                hash = hash::hash_string(chars, Size - 1 /* Don't hash the terminating 0 */);
            }

            [[gnu::always_inline]] constexpr operator uint64_t() const
            {
                return hash;
            }

            uint64_t hash;

            static_assert(!std::is_convertible_v<string_hasher<Size>, const char *>,
                          "Hashing const char * to const char * is insane, and will lead to bugs");
        };

        // A debug string
        // This ensures it'll never be in the compiled program unless _HXP_DEBUG is defined
        template <size_t Size>
        struct debug_string {
            consteval debug_string(const char (&chars)[Size])
            {
#if defined(_HXP_DEBUG)
                for (size_t index = 0; index < Size; ++index)
                    contents[index] = chars[index];
#else
                (void) chars;
#endif
            }

            [[gnu::always_inline]] constexpr operator strings::debug_only() const
            {
                return debug_only {
#if defined(_HXP_DEBUG)
                    contents.data()
#else
                    nullptr
#endif
                };
            }

#if defined(_HXP_DEBUG)
            std::array<char, Size> contents;
#endif
        };
    }

    // Literals to generate the strings
    inline namespace literals {
        template <gen::string_wrapper Wrapper>
        consteval auto operator""_hide() { return Wrapper; }

        template <gen::string_hasher Hasher>
        consteval auto operator""_hash() { return Hasher; }

        template <gen::debug_string Debug>
        consteval auto operator""_debug() { return Debug; }
    }

    // itoa helper
    template <typename T, typename Limits = std::numeric_limits<T>>
    constexpr size_t itoa_size_v = 1 + Limits::digits10 + (Limits::is_signed ? 1 : 0);

    template <typename T>
    [[gnu::always_inline]] inline std::array<char, itoa_size_v<T>> itoa(T value)
    {
        std::array<char, itoa_size_v<T>> buffer = {};

        if (!value) {
            buffer[0] = '0';
            return buffer;
        }

        std::make_unsigned_t<T> print;
        size_t index = 0;

        if constexpr (std::is_signed_v<T>) {
            if (value == std::numeric_limits<T>::min()) {
                print = static_cast<std::make_unsigned_t<T>>(std::numeric_limits<T>::max()) + 1u;
                buffer[index++] = '-';
            } else if (value < static_cast<T>(0)) {
                print = -value;
                buffer[index++] = '-';
            } else {
                print = value;
            }
        } else {
            print = value;
        }

        size_t width = 0;
        for (auto copy = print; copy; ++width)
            copy /= 10;

        for (; print; print /= 10)
            buffer[index + --width] = "0123456789"[print % 10];

        return buffer;
    }

    // atoi helper
    template <typename T>
    [[gnu::always_inline]] inline T atoi_digit(char c)
    {
        switch (c) {
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            case '8': return 8;
            case '9': return 9;
            default: return 0;
        }
    }

    template <typename T>
    [[gnu::always_inline]] inline T atoi(const char *data, size_t size = static_cast<size_t>(-1l))
    {
        T value = static_cast<T>(0);

        if (size == static_cast<size_t>(-1l))
            size = utils::strlen(data);

        if constexpr (std::is_signed_v<T>) {
            if (size && data[0] == '-') {
                auto remainder = atoi<std::make_unsigned_t<T>>(&data[1], size - 1);
                if (remainder > static_cast<decltype(remainder)>(std::numeric_limits<T>::max()))
                    return std::numeric_limits<T>::min();
                return -static_cast<T>(remainder);
            }
        }

        for (size_t i = 0; i < size; ++i)
            value = static_cast<T>(10) * value + atoi_digit<T>(data[i]);

        return value;
    }
}

