#pragma once
#include "utils.h"

#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <tuple>
#include <type_traits>

namespace testing {
    [[gnu::always_inline, gnu::no_instrument_function]]
    inline constexpr char nibble(uint8_t value)
    {
        return (value < 0xa) ? ('0' + value) : ('a' + (value - 0xa));
    }

    template <typename T>
    [[gnu::no_instrument_function]]
    constexpr inline std::array<char, 2 * sizeof(T)> hexdump(const T &t)
    {
        std::array<char, 2 * sizeof(T)> hex;
        const char *raw = reinterpret_cast<const char *>(&t);
        for (size_t i = 0; i < sizeof(T); ++i) {
            hex[2 * i] = nibble(static_cast<uint8_t>(raw[i]) >> 4);
            hex[2 * i + 1] = nibble(static_cast<uint8_t>(raw[i]) & 0xf);
        }
        return hex;
    }

    template <typename T>
    [[gnu::no_instrument_function]]
    constexpr inline auto hex_number(const T t)
    {
        static_assert(std::is_integral_v<T>, "Can't print this type as a hexadecimal number");
        std::array<char, 2 * sizeof(T)> hex;
        for (size_t i = 0; i < 2 * sizeof(T); ++i)
            hex[i] = nibble(static_cast<uint8_t>((t >> (8 * sizeof(T) - 4 * (i + 1))) & 0xf));
        return hex;
    }

    template <typename T>
    [[gnu::no_instrument_function]]
    constexpr inline auto dec_number(T t)
    {
        static_assert(std::is_integral_v<T>, "Can't print this type as a hexadecimal number");
        // This will be padded with null bytes, sorry. strlen it if you really have to,
        // that's why we have a + 1 always. And another + 1 for the sign.
        std::array<char, 3 * sizeof(T) + 2> dec;
        __builtin_memset_inline(dec.data(), 0, dec.size());

        if (!t) {
            dec[0] = '0';
            return dec;
        }

        constexpr size_t start_index = dec.size() - 2;
        size_t index = start_index;
        bool negative = std::is_signed_v<T> && t < 0;

        while (t) {
            dec[index--] = '0' + (t % 10);
            t /= 10;
        }

        if (negative)
            dec[index--] = '-';

        size_t bytes = start_index - index + 1 /* Copy the final null byte */;
        ++index;
        for (size_t offset = 0; offset < bytes; ++offset)
            dec[offset] = dec[index + offset];

        return dec;
    }

    [[gnu::no_instrument_function]]
    inline void log(const char *message, size_t length = static_cast<size_t>(-1l))
    {
        // __builtin_strlen will often call strlen(), so don't do that.
        if (length == static_cast<size_t>(-1l)) {
            length = 0;
            while (message[length])
                ++length;
        }
        std::ignore = sys::write(STDERR_FILENO, message, length);
    }

    template <size_t Size>
    [[gnu::no_instrument_function]]
    inline void log(const std::array<char, Size> &message)
    {
        if (!message[Size - 1])
            log(message.data());
        else
            log(message.data(), message.size());
    }

    template <typename... Args>
    [[gnu::no_instrument_function]]
    inline void logln(Args &&...args) {
        log(std::forward<Args>(args)...);
        log("\n", 1);
    }
}
