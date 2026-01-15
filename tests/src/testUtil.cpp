#include <gtest/gtest.h>

#include <fpcap/MagicNumber.hpp>
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
    // Note: the implementation returns 2 << remainingBits which is 2^(remainingBits+1)
    const uint32_t result = fpcap::util::fromIfTsresolUInt(0x86);
    EXPECT_EQ(result, 2u << 6); // 128
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
    uint32_t microseconds = 0;
    fpcap::util::calculateTimestamps(timestampResolution, timestampHigh, timestampLow,
                                     &seconds, &microseconds);

    EXPECT_EQ(seconds, 1234567890u);
    EXPECT_EQ(microseconds, 123456u);
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
