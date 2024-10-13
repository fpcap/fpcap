#ifndef FPCAP_UTIL_HPP
#define FPCAP_UTIL_HPP

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <cassert>
#include <optional>

#if DEBUG
#define FPCAP_DEBUG_LOG(format) printf(format);
#define FPCAP_DEBUG_LOG_1(format, val) printf(format, val);
#define FPCAP_DEBUG_LOG_2(format, val1, val2) printf(format, val1, val2);
#define FPCAP_ASSERT(x) assert(x)
#else
#define FPCAP_DEBUG_LOG(format) (void)(format)
#define FPCAP_DEBUG_LOG_1(format, val) (void)(format)
#define FPCAP_DEBUG_LOG_2(format, val1, val2) (void)(format)
#define FPCAP_ASSERT(x) (void)(x)
#endif
#define FPCAP_WARN(msg) fprintf(stderr, msg)
#define FPCAP_WARN_1(msg, val) fprintf(stderr, msg, val)

namespace fpcap::util {
/**
 * Reads first 32 bits from a file to determine the magic number / file format.
 * @param filepath Path to the file as string
 * @return The first 32 bits as unsigned
 */
[[maybe_unused]] static std::optional<uint32_t> read32bitsFromFile(const std::string& filepath) {
    uint32_t magicNumber = 0;
    if (std::ifstream file(filepath, std::ios::in | std::ios::binary); file.is_open()) {
        file.read(reinterpret_cast<char*>(&magicNumber), sizeof(magicNumber));
        return magicNumber;
    }
    return std::nullopt;
}

[[maybe_unused]] static void dumpMemory(const uint8_t* data, const size_t length) {
    for (size_t i = 1; i <= length; i++) {
        printf("%02hhx", data[i - 1]);
        if (i % 16 == 0) {
            putchar('\n');
        }
        else if (i % 8 == 0) {
            printf("  ");
        }
        else {
            putchar(' ');
        }
    }
    putchar('\n');
}

[[maybe_unused]] static double fromIfTsresolDouble(const uint8_t value) {
    const uint8_t mostSignificantBit = value & 0x80u;
    const uint8_t remainingBits = value & 0x7Fu;

    // TODO test this code
    if (mostSignificantBit == 0) {
        // most significant bit is 0, rest of bits is negative power of 10
        return std::pow(10, -remainingBits);
    }
    else {
        // most significant bit is 1, rest of bits is negative power of 2
        return std::pow(2, -remainingBits);
    }
}

[[maybe_unused]] static uint32_t fromIfTsresolUInt(const uint8_t value) {
    const uint8_t mostSignificantBit = value & 0x80u;
    const uint8_t remainingBits = value & 0x7Fu;

    // TODO test this code
    if (mostSignificantBit == 0) {
        // most significant bit is 0, rest of bits is negative power of 10
        uint32_t result = 1;
        for (auto i = 0u; i < remainingBits; ++i) {
            result *= 10;
        }
        return result;
    }

    // most significant bit is 1, rest of bits is negative power of 2
    return 2 << remainingBits;
}

[[maybe_unused]] static void calculateTimestamps(const uint32_t timestampResolution,
                                                 const uint32_t timestampHigh,
                                                 const uint32_t timestampLow,
                                                 uint32_t* timestampSeconds,
                                                 uint32_t* timestampMicroseconds) {
    const uint64_t timestamp = static_cast<uint64_t>(timestampHigh) << 32 | timestampLow;
    const uint64_t sec = timestamp / timestampResolution;
    *timestampSeconds = static_cast<uint32_t>(sec);
    *timestampMicroseconds = static_cast<uint32_t>(timestamp - sec * timestampResolution);
}
}

#endif // FPCAP_UTIL_HPP
