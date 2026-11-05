#ifndef FPCAP_UTIL_HPP
#define FPCAP_UTIL_HPP

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>

#if FPCAP_DEBUG_LOGGING
#define FPCAP_DEBUG_LOG(format) printf(format);
#define FPCAP_DEBUG_LOG_1(format, val) printf(format, val);
#define FPCAP_DEBUG_LOG_2(format, val1, val2) printf(format, val1, val2);
#else
#define FPCAP_DEBUG_LOG(format) (void)(format)
#define FPCAP_DEBUG_LOG_1(format, val) (void)(format)
#define FPCAP_DEBUG_LOG_2(format, val1, val2) (void)(format)
#endif

#if DEBUG
#define FPCAP_ASSERT(x) assert(x)
#else
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
[[maybe_unused]] static std::optional<uint32_t>
read32bitsFromFile(const std::string& filepath) {
    uint32_t magicNumber = 0;
    if (std::ifstream file(filepath, std::ios::in | std::ios::binary); file.is_open()) {
        file.read(reinterpret_cast<char*>(&magicNumber), sizeof(magicNumber));
        return magicNumber;
    }
    return std::nullopt;
}

[[maybe_unused]] static uint16_t byteSwap16(const uint16_t value) {
    return static_cast<uint16_t>(value << 8 | value >> 8);
}

[[maybe_unused]] static uint32_t byteSwap32(const uint32_t value) {
    return value << 24 | (value & 0x0000FF00) << 8 | (value & 0x00FF0000) >> 8 |
           value >> 24;
}

[[maybe_unused]] static void dumpMemory(const uint8_t* data, const size_t length) {
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

[[maybe_unused]] static double fromIfTsresolDouble(const uint8_t value) {
    const uint8_t mostSignificantBit = value & 0x80u;
    const uint8_t remainingBits = value & 0x7Fu;

    if (mostSignificantBit == 0) {
        // most significant bit is 0, rest of bits is negative power of 10
        return std::pow(10, -remainingBits);
    }

    // most significant bit is 1, rest of bits is negative power of 2
    return std::pow(2, -remainingBits);
}

/**
 * Converts the value of an if_tsresol option into the number of timestamp ticks per
 * second. If the most significant bit is 0, the remaining bits are a negative power of
 * 10, otherwise a negative power of 2. Resolutions that do not fit into 32 bits
 * (finer than 10^-9 or 2^-31 seconds) are not supported and cause an exception, since
 * they would otherwise silently overflow or lead to a division by zero.
 */
[[maybe_unused]] static uint32_t fromIfTsresolUInt(const uint8_t value) {
    const uint8_t mostSignificantBit = value & 0x80u;
    const uint8_t remainingBits = value & 0x7Fu;

    if (mostSignificantBit == 0) {
        // most significant bit is 0, rest of bits is negative power of 10
        if (remainingBits > 9) {
            throw std::runtime_error("unsupported if_tsresol value: 10^-" +
                                     std::to_string(remainingBits) +
                                     " exceeds the supported resolution of 10^-9");
        }
        uint32_t result = 1;
        for (auto i = 0u; i < remainingBits; ++i) {
            result *= 10;
        }
        return result;
    }

    // most significant bit is 1, rest of bits is negative power of 2
    if (remainingBits > 31) {
        throw std::runtime_error("unsupported if_tsresol value: 2^-" +
                                 std::to_string(remainingBits) +
                                 " exceeds the supported resolution of 2^-31");
    }
    return 1u << remainingBits;
}

/**
 * Splits a 64 bit PcapNG timestamp into seconds and subseconds. The subseconds are
 * expressed in ticks of the given resolution (e.g. nanoseconds for a resolution of
 * 10^9), not necessarily in microseconds.
 */
[[maybe_unused]] static void calculateTimestamps(const uint32_t timestampResolution,
                                                 const uint32_t timestampHigh,
                                                 const uint32_t timestampLow,
                                                 uint32_t* timestampSeconds,
                                                 uint32_t* timestampSubseconds) {
    if (timestampResolution == 0) {
        throw std::runtime_error("timestamp resolution must not be zero");
    }
    const uint64_t timestamp = static_cast<uint64_t>(timestampHigh) << 32 | timestampLow;
    const uint64_t sec = timestamp / timestampResolution;
    *timestampSeconds = static_cast<uint32_t>(sec);
    *timestampSubseconds = static_cast<uint32_t>(timestamp - sec * timestampResolution);
}

/**
 * Converts subseconds expressed in ticks of the given resolution into microseconds.
 * Finer resolutions are truncated, matching how nanosecond pcap files are handled.
 */
[[maybe_unused]] static uint32_t subsecondsToMicroseconds(const uint32_t subseconds,
                                                          const uint32_t timestampResolution) {
    if (timestampResolution == 1'000'000) {
        return subseconds;
    }
    if (timestampResolution == 0) {
        throw std::runtime_error("timestamp resolution must not be zero");
    }
    // subseconds < 2^32 and 10^6 < 2^20, so the product always fits into 64 bits
    return static_cast<uint32_t>(static_cast<uint64_t>(subseconds) * 1'000'000 /
                                 timestampResolution);
}

/**
 * Splits a 64 bit PcapNG timestamp into seconds and microseconds, independent of the
 * resolution the timestamp was recorded in.
 */
[[maybe_unused]] static void calculateTimestampsMicroseconds(
    const uint32_t timestampResolution, const uint32_t timestampHigh,
    const uint32_t timestampLow, uint32_t* timestampSeconds,
    uint32_t* timestampMicroseconds) {
    uint32_t subseconds = 0;
    calculateTimestamps(timestampResolution, timestampHigh, timestampLow, timestampSeconds,
                        &subseconds);
    *timestampMicroseconds = subsecondsToMicroseconds(subseconds, timestampResolution);
}
} // namespace fpcap::util

#endif // FPCAP_UTIL_HPP
