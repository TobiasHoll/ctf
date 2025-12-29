#pragma once
#include <cstdint>
#include <cstddef>
#include <string_view>
#include <source_location>

namespace hash {
    constexpr static uint64_t hash_string(const char *data, size_t size = static_cast<size_t>(-1l),
                                          uint64_t base = static_cast<uint64_t>(-1l))
    {
        uint64_t hash = base;
        for (size_t i = 0; i < size && (size != static_cast<size_t>(-1l) || data[i] != 0); ++i)
            hash = (hash * 0x100000001b3ul) ^ static_cast<uint64_t>(data[i]);
        return hash;
    }

    consteval static inline uint64_t hash_location(const std::source_location location)
    {
        uint64_t hash = (static_cast<uint64_t>(location.line()) << 32) | location.column();
        std::string_view file_name = location.file_name();
        std::string_view function_name = location.file_name();
        hash = hash_string(file_name.data(), file_name.size(), hash);
        hash = hash_string(function_name.data(), function_name.size(), hash);
        return hash;
    }

    constexpr static inline uint64_t xorshift64(uint64_t state)
    {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }
}
