#include <gtest/gtest.h>

#include <fpcap/Constants.hpp>
#include <fpcap/util.hpp>

#include <cmath>
#include <filesystem>
#include <fstream>

// read32bitsFromFile tests

TEST(Util, Read32bitsValidPcapFile) {
    const auto result = fpcap::util::read32bitsFromFile("tracefiles/example.pcap");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), fpcap::PCAP_MICROSECONDS);
}

TEST(Util, Read32bitsValidPcapNgFile) {
    const auto result =
        fpcap::util::read32bitsFromFile("tracefiles/pcapng-example.pcapng");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), fpcap::PCAPNG);
}

TEST(Util, Read32bitsValidModifiedPcapFile) {
    const auto result = fpcap::util::read32bitsFromFile("tracefiles/fritzbox-ip.pcap");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), fpcap::MODIFIED_PCAP);
}

TEST(Util, Read32bitsMissingFile) {
    const auto result = fpcap::util::read32bitsFromFile("nonexistent-file.bin");
    EXPECT_FALSE(result.has_value());
}

TEST(Util, Read32bitsCustomData) {
    const auto tempFile = std::filesystem::temp_directory_path() / "fpcap_util_test.bin";
    {
        std::ofstream file(tempFile, std::ios::binary);
        uint32_t testValue = 0x12345678;
        file.write(reinterpret_cast<char*>(&testValue), sizeof(testValue));
    }

    const auto result = fpcap::util::read32bitsFromFile(tempFile.string());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 0x12345678u);

    std::filesystem::remove(tempFile);
}

// fromIfTsresolDouble tests (timestamp resolution for PCAPNG)
// MSB=0: remaining bits are negative power of 10
// MSB=1: remaining bits are negative power of 2

TEST(Util, FromIfTsresolDoublePowerOf10) {
    // Value 6 (MSB=0, remaining=6) means 10^-6 = microseconds
    const double result = fpcap::util::fromIfTsresolDouble(6);
    EXPECT_DOUBLE_EQ(result, 1e-6);
}

TEST(Util, FromIfTsresolDoublePowerOf10_Nanoseconds) {
    // Value 9 (MSB=0, remaining=9) means 10^-9 = nanoseconds
    const double result = fpcap::util::fromIfTsresolDouble(9);
    EXPECT_DOUBLE_EQ(result, 1e-9);
}

TEST(Util, FromIfTsresolDoublePowerOf2) {
    // Value 0x86 (MSB=1, remaining=6) means 2^-6 = 1/64
    const double result = fpcap::util::fromIfTsresolDouble(0x86);
    EXPECT_DOUBLE_EQ(result, std::pow(2, -6));
}

TEST(Util, FromIfTsresolDoublePowerOf2_High) {
    // Value 0x94 (MSB=1, remaining=20) means 2^-20
    const double result = fpcap::util::fromIfTsresolDouble(0x94);
    EXPECT_DOUBLE_EQ(result, std::pow(2, -20));
}

// fromIfTsresolUInt tests

TEST(Util, FromIfTsresolUIntPowerOf10_Microseconds) {
    // Value 6 (MSB=0, remaining=6) means 10^6 = 1000000
    const uint32_t result = fpcap::util::fromIfTsresolUInt(6);
    EXPECT_EQ(result, 1000000u);
}

TEST(Util, FromIfTsresolUIntPowerOf10_Nanoseconds) {
    // Value 9 (MSB=0, remaining=9) means 10^9 = 1000000000
    const uint32_t result = fpcap::util::fromIfTsresolUInt(9);
    EXPECT_EQ(result, 1000000000u);
}

TEST(Util, FromIfTsresolUIntPowerOf2) {
    // Value 0x86 (MSB=1, remaining=6) means 2^6 = 64
    const uint32_t result = fpcap::util::fromIfTsresolUInt(0x86);
    EXPECT_EQ(result, 1u << 6); // 64
}

// calculateTimestamps tests

TEST(Util, CalculateTimestampsMicroseconds) {
    // 1000000 ticks per second (microseconds)
    // timestamp = 1234567890 * 1000000 + 123456 = 1234567890123456
    constexpr uint32_t timestampResolution = 1000000;
    constexpr uint64_t fullTimestamp = 1234567890ULL * 1000000 + 123456;
    constexpr uint32_t timestampHigh = fullTimestamp >> 32;
    constexpr uint32_t timestampLow = fullTimestamp & 0xFFFFFFFF;

    uint32_t seconds = 0;
    uint32_t subseconds = 0;
    fpcap::util::calculateTimestamps(timestampResolution, timestampHigh, timestampLow,
                                     &seconds, &subseconds);

    EXPECT_EQ(seconds, 1234567890u);
    EXPECT_EQ(subseconds, 123456u);
}

TEST(Util, CalculateTimestampsNanoseconds) {
    // 1000000000 ticks per second (nanoseconds)
    constexpr uint32_t timestampResolution = 1000000000;
    constexpr uint64_t fullTimestamp = 100ULL * 1000000000 + 500000000; // 100.5 seconds
    constexpr uint32_t timestampHigh = fullTimestamp >> 32;
    constexpr uint32_t timestampLow = fullTimestamp & 0xFFFFFFFF;

    uint32_t seconds = 0;
    uint32_t nanoseconds = 0;
    fpcap::util::calculateTimestamps(timestampResolution, timestampHigh, timestampLow,
                                     &seconds, &nanoseconds);

    EXPECT_EQ(seconds, 100u);
    EXPECT_EQ(nanoseconds, 500000000u);
}

TEST(Util, CalculateTimestampsZero) {
    constexpr uint32_t timestampResolution = 1000000;
    constexpr uint32_t timestampHigh = 0;
    constexpr uint32_t timestampLow = 0;

    uint32_t seconds = 0;
    uint32_t microseconds = 0;
    fpcap::util::calculateTimestamps(timestampResolution, timestampHigh, timestampLow,
                                     &seconds, &microseconds);

    EXPECT_EQ(seconds, 0u);
    EXPECT_EQ(microseconds, 0u);
}

// fromIfTsresolUInt range checks

TEST(Util, FromIfTsresolUIntPowerOf10_Seconds) {
    EXPECT_EQ(fpcap::util::fromIfTsresolUInt(0x00), 1u);
}

TEST(Util, FromIfTsresolUIntPowerOf10_TooFineThrows) {
    // 10^-10 and finer do not fit into 32 bits; previously these silently wrapped
    // around (e.g. 0x0A -> 1410065408) or became 0 for exponents >= 32.
    EXPECT_THROW(fpcap::util::fromIfTsresolUInt(0x0A), std::runtime_error);
    EXPECT_THROW(fpcap::util::fromIfTsresolUInt(0x20), std::runtime_error);
    EXPECT_THROW(fpcap::util::fromIfTsresolUInt(0x7F), std::runtime_error);
}

TEST(Util, FromIfTsresolUIntPowerOf2_Boundaries) {
    EXPECT_EQ(fpcap::util::fromIfTsresolUInt(0x80), 1u);
    EXPECT_EQ(fpcap::util::fromIfTsresolUInt(0x80 | 31), 1u << 31);
}

TEST(Util, FromIfTsresolUIntPowerOf2_TooFineThrows) {
    // 1u << 32 and beyond is undefined behaviour
    EXPECT_THROW(fpcap::util::fromIfTsresolUInt(0x80 | 32), std::runtime_error);
    EXPECT_THROW(fpcap::util::fromIfTsresolUInt(0xFF), std::runtime_error);
}

TEST(Util, FromIfTsresolUIntAllValidValuesAreNonZero) {
    for (uint32_t value = 0; value <= 0xFF; ++value) {
        const auto byte = static_cast<uint8_t>(value);
        try {
            EXPECT_NE(fpcap::util::fromIfTsresolUInt(byte), 0u) << "value: " << value;
        } catch (const std::runtime_error&) {
            // rejected values are fine, they must just never yield a zero resolution
        }
    }
}

// calculateTimestamps edge cases

TEST(Util, CalculateTimestampsZeroResolutionThrows) {
    uint32_t seconds = 0;
    uint32_t subseconds = 0;
    EXPECT_THROW(fpcap::util::calculateTimestamps(0, 0, 1, &seconds, &subseconds),
                 std::runtime_error);
}

TEST(Util, CalculateTimestampsPowerOf2) {
    // 2^-10 resolution: 1024 ticks per second, 5.5 seconds
    constexpr uint32_t timestampResolution = 1024;
    uint32_t seconds = 0;
    uint32_t subseconds = 0;
    fpcap::util::calculateTimestamps(timestampResolution, 0, 5 * 1024 + 512, &seconds,
                                     &subseconds);
    EXPECT_EQ(seconds, 5u);
    EXPECT_EQ(subseconds, 512u);
}

// subsecondsToMicroseconds tests

TEST(Util, SubsecondsToMicroseconds) {
    using fpcap::util::subsecondsToMicroseconds;
    EXPECT_EQ(subsecondsToMicroseconds(123456, 1'000'000), 123456u);
    EXPECT_EQ(subsecondsToMicroseconds(123456789, 1'000'000'000), 123456u); // truncates
    EXPECT_EQ(subsecondsToMicroseconds(999999999, 1'000'000'000), 999999u);
    EXPECT_EQ(subsecondsToMicroseconds(250, 1'000), 250000u);            // milliseconds
    EXPECT_EQ(subsecondsToMicroseconds(0, 1), 0u);                      // seconds
    EXPECT_EQ(subsecondsToMicroseconds(512, 1024), 500000u);            // 2^-10
    EXPECT_EQ(subsecondsToMicroseconds((1u << 31) - 1, 1u << 31), 999999u); // 2^-31
}

TEST(Util, SubsecondsToMicrosecondsZeroResolutionThrows) {
    EXPECT_THROW(fpcap::util::subsecondsToMicroseconds(1, 0), std::runtime_error);
}

// calculateTimestampsMicroseconds tests

TEST(Util, CalculateTimestampsMicrosecondsFromNanoseconds) {
    // Regression test: a nanosecond resolution timestamp must yield microseconds, not
    // nanoseconds, since Packet::timestampMicroseconds is in microseconds.
    constexpr uint32_t timestampResolution = 1'000'000'000;
    constexpr uint64_t fullTimestamp = 1234567890ULL * 1'000'000'000 + 123456789;
    constexpr uint32_t timestampHigh = fullTimestamp >> 32;
    constexpr uint32_t timestampLow = fullTimestamp & 0xFFFFFFFF;

    uint32_t seconds = 0;
    uint32_t microseconds = 0;
    fpcap::util::calculateTimestampsMicroseconds(timestampResolution, timestampHigh,
                                                 timestampLow, &seconds, &microseconds);

    EXPECT_EQ(seconds, 1234567890u);
    EXPECT_EQ(microseconds, 123456u);
}

TEST(Util, CalculateTimestampsMicrosecondsFromMicroseconds) {
    constexpr uint32_t timestampResolution = 1'000'000;
    constexpr uint64_t fullTimestamp = 1234567890ULL * 1'000'000 + 123456;
    constexpr uint32_t timestampHigh = fullTimestamp >> 32;
    constexpr uint32_t timestampLow = fullTimestamp & 0xFFFFFFFF;

    uint32_t seconds = 0;
    uint32_t microseconds = 0;
    fpcap::util::calculateTimestampsMicroseconds(timestampResolution, timestampHigh,
                                                 timestampLow, &seconds, &microseconds);

    EXPECT_EQ(seconds, 1234567890u);
    EXPECT_EQ(microseconds, 123456u);
}
