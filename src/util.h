#ifndef MMPR_UTIL_H
#define MMPR_UTIL_H

#include <cmath>
#include <cstdint>
#include <cstdio>

namespace mmpr {
namespace util {

static void dumpMemory(const uint8_t* data, size_t length) {
    for (size_t i = 1; i <= length; i++) {
        printf("%02hhx", data[i - 1]);
        if (i % 16 == 0) {
            putchar('\n');
        } else if (i % 8 == 0) {
            printf("  ");
        } else {
            putchar(' ');
        }
    }
    putchar('\n');
}

static double fromIfTsresolDouble(const uint8_t value) {
    uint8_t mostSignificantBit = value & 0x80;
    uint8_t remainingBits = value & 0x7F;

    if (mostSignificantBit == 0) {
        // most significant bit is 0, rest of bits is negative power of 10
        return std::pow(10, -remainingBits);
    } else {
        // most signiticant bit is 1, rest of bits is negative power of 2
        return std::pow(2, -remainingBits);
    }
}

static uint32_t fromIfTsresolUInt(const uint8_t value) {
    uint8_t mostSignificantBit = value & 0x80;
    uint8_t remainingBits = value & 0x7F;

    if (mostSignificantBit == 0) {
        // most significant bit is 0, rest of bits is negative power of 10
        return std::pow(10, remainingBits);
    } else {
        // most signiticant bit is 1, rest of bits is negative power of 2
        return std::pow(2, remainingBits);
    }
}

inline static void calculateTimestamps(uint32_t timestampResolution,
                                       uint32_t timestampHigh,
                                       uint32_t timestampLow,
                                       uint32_t* timestampSeconds,
                                       uint32_t* timestampMicroseconds) {
    uint64_t timestamp = (uint64_t)timestampHigh << 32 | timestampLow;
    uint64_t sec = timestamp / timestampResolution;
    *timestampSeconds = sec;
    *timestampMicroseconds = timestamp - sec * timestampResolution;
}

} // namespace util
} // namespace mmpr

#endif // MMPR_UTIL_H
