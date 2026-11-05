#include <gtest/gtest.h>

#include "../TestFiles.hpp"

#include <fpcap/Constants.hpp>
#include <fpcap/PacketReader.hpp>
#include <fpcap/filesystem/Reader.hpp>

#include <vector>

namespace {
using fpcap::test::TempFile;

void expectAllReadersThrow(const std::vector<uint8_t>& bytes) {
    const TempFile file{bytes};
    EXPECT_THROW(fpcap::PacketReader(file.path(), true), std::runtime_error);
    EXPECT_THROW(fpcap::PacketReader(file.path(), false), std::runtime_error);
    EXPECT_THROW(fpcap::Reader::getReader(file.path()), std::runtime_error);
}

void append32(std::vector<uint8_t>& bytes, const uint32_t value, const bool bigEndian) {
    for (int i = 0; i < 4; ++i) {
        const int shift = bigEndian ? 24 - 8 * i : 8 * i;
        bytes.push_back(static_cast<uint8_t>(value >> shift));
    }
}

// File header followed by one record of recordHeaderLength bytes that claims
// captureLength bytes of data and holds dataLength
std::vector<uint8_t> makeFile(const uint32_t magic,
                              const size_t recordHeaderLength,
                              const uint32_t captureLength,
                              const size_t dataLength,
                              const bool bigEndian = false) {
    std::vector<uint8_t> bytes;
    const uint32_t header[] = {magic, 0, 0, 0, 65535, 1};
    for (const uint32_t value : header) {
        append32(bytes, value, bigEndian);
    }
    // version 2.4 as two 16-bit fields
    bytes[4] = bigEndian ? 0 : 2;
    bytes[5] = bigEndian ? 2 : 0;
    bytes[6] = bigEndian ? 0 : 4;
    bytes[7] = bigEndian ? 4 : 0;
    const uint32_t record[] = {1700000000, 0, captureLength, captureLength};
    for (const uint32_t value : record) {
        append32(bytes, value, bigEndian);
    }
    bytes.resize(bytes.size() + recordHeaderLength - 16 + dataLength, 0xAB);
    return bytes;
}

// Reads with the isExhausted() loop the examples use, giving up instead of hanging
void expectExhaustsAfter(const std::vector<uint8_t>& bytes, const size_t packets) {
    const TempFile file{bytes};
    for (const bool mmap : {true, false}) {
        fpcap::PacketReader reader{file.path(), mmap};
        fpcap::Packet packet;
        size_t count = 0;
        for (int i = 0; i < 10 && !reader.isExhausted(); ++i) {
            if (reader.nextPacket(packet)) {
                ++count;
            }
        }
        EXPECT_TRUE(reader.isExhausted()) << "mmap=" << mmap;
        EXPECT_EQ(count, packets) << "mmap=" << mmap;
    }
}
} // namespace

TEST(TruncatedPcapReader, MagicOnly) {
    expectAllReadersThrow({0xD4, 0xC3, 0xB2, 0xA1});
}

TEST(TruncatedPcapReader, ShortFileHeader) {
    expectAllReadersThrow({0xD4, 0xC3, 0xB2, 0xA1, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF});
}

TEST(TruncatedPcapReader, ZstdShortFileHeader) {
    // zstd frame of the 20 bytes from ShortFileHeader
    expectAllReadersThrow({0x28, 0xB5, 0x2F, 0xFD, 0x24, 0x14, 0x8D, 0x00, 0x00, 0x58,
                           0xD4, 0xC3, 0xB2, 0xA1, 0x00, 0x02, 0x00, 0x04, 0x00, 0xFF,
                           0xFF, 0x01, 0x00, 0x05, 0x38, 0x02, 0x5F, 0x72, 0x00, 0x92});
}

TEST(TruncatedPcapReader, ZstdShorterThanMagic) {
    // zstd frame of the two bytes D4 C3
    expectAllReadersThrow({0x28, 0xB5, 0x2F, 0xFD, 0x24, 0x02, 0x11, 0x00, 0x00, 0xD4,
                           0xC3, 0xC6, 0x0B, 0xBD, 0x77});
}

TEST(TruncatedPcapReader, TrailingPartialRecordHeader) {
    auto bytes = makeFile(fpcap::PCAP_MICROSECONDS, 16, 4, 4);
    bytes.resize(bytes.size() + 5, 0);
    expectExhaustsAfter(bytes, 1);
}

TEST(TruncatedModifiedPcapReader, MagicOnly) {
    expectAllReadersThrow({0x34, 0xCD, 0xB2, 0xA1});
}

TEST(TruncatedModifiedPcapReader, ShortFileHeader) {
    expectAllReadersThrow({0x34, 0xCD, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00});
}

TEST(TruncatedModifiedPcapReader, ZstdShortFileHeader) {
    // zstd frame of the 20 bytes from ShortFileHeader
    expectAllReadersThrow({0x28, 0xB5, 0x2F, 0xFD, 0x24, 0x14, 0xA1, 0x00, 0x00,
                           0x34, 0xCD, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                           0x00, 0x00, 0x5D, 0x60, 0x1C, 0x05});
}

TEST(TruncatedModifiedPcapReader, TrailingPartialRecordHeader) {
    auto bytes = makeFile(fpcap::MODIFIED_PCAP, 24, 4, 4);
    bytes.resize(bytes.size() + 5, 0);
    expectExhaustsAfter(bytes, 1);
}

TEST(TruncatedModifiedPcapReader, CaptureLengthBeyondFile) {
    expectExhaustsAfter(makeFile(fpcap::MODIFIED_PCAP, 24, 100, 10), 0);
}

TEST(TruncatedModifiedPcapReader, BigEndianTrailingPartialRecordHeader) {
    auto bytes = makeFile(fpcap::MODIFIED_PCAP, 24, 4, 4, true);
    bytes.resize(bytes.size() + 5, 0);
    expectExhaustsAfter(bytes, 1);
}

TEST(TruncatedModifiedPcapReader, BigEndianCaptureLengthBeyondFile) {
    expectExhaustsAfter(makeFile(fpcap::MODIFIED_PCAP, 24, 100, 10, true), 0);
}

TEST(TruncatedPcapReader, BigEndianTrailingPartialRecordHeader) {
    auto bytes = makeFile(fpcap::PCAP_MICROSECONDS, 16, 4, 4, true);
    bytes.resize(bytes.size() + 5, 0);
    expectExhaustsAfter(bytes, 1);
}

TEST(TruncatedPcapReader, BigEndianCaptureLengthBeyondFile) {
    expectExhaustsAfter(makeFile(fpcap::PCAP_MICROSECONDS, 16, 100, 10, true), 0);
}
