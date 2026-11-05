#include <gtest/gtest.h>

#include "../TestFiles.hpp"

#include <fpcap/Constants.hpp>
#include <fpcap/PacketReader.hpp>
#include <fpcap/filesystem/Reader.hpp>
#include <fpcap/modified_pcap/ModifiedPcapParser.hpp>

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {
using fpcap::test::putSwapped16;
using fpcap::test::putSwapped32;
using fpcap::test::TempFile;

const std::string FRITZBOX = "tracefiles/fritzbox-ip.pcap";

struct ExpectedPacket {
    uint32_t timestampSeconds;
    uint32_t timestampMicroseconds;
    uint32_t length;
};

constexpr std::array<ExpectedPacket, 5> FRITZBOX_PACKETS{{
    {1657408804, 613758, 72},
    {1657408806, 315741, 60},
    {1657408806, 317496, 60},
    {1657408807, 568598, 69},
    {1657408807, 578653, 140},
}};

template <typename TNextPacket>
void expectFritzboxPackets(TNextPacket nextPacket, const std::string& nativePath) {
    std::ifstream in(nativePath, std::ios::binary);
    const std::vector<uint8_t> native{std::istreambuf_iterator<char>(in), {}};
    fpcap::Packet packet;
    size_t index = 0;
    size_t offset = 24;
    while (nextPacket(packet)) {
        ASSERT_LT(index, FRITZBOX_PACKETS.size());
        const auto& expected = FRITZBOX_PACKETS[index];
        EXPECT_EQ(packet.timestampSeconds, expected.timestampSeconds) << index;
        EXPECT_EQ(packet.timestampMicroseconds, expected.timestampMicroseconds) << index;
        EXPECT_EQ(packet.captureLength, expected.length) << index;
        EXPECT_EQ(packet.length, expected.length) << index;
        EXPECT_EQ(packet.dataLinkType, fpcap::DLT_RAW) << index;
        ASSERT_LE(offset + 24 + expected.length, native.size());
        EXPECT_EQ(std::memcmp(packet.data, &native[offset + 24], expected.length), 0)
            << index;
        offset += 24 + expected.length;
        ++index;
    }
    EXPECT_EQ(index, FRITZBOX_PACKETS.size());
}

void expectFritzboxPackets(const std::string& filepath) {
    for (const bool mmap : {true, false}) {
        SCOPED_TRACE("mmap=" + std::to_string(mmap));
        fpcap::PacketReader reader{filepath, mmap};
        expectFritzboxPackets([&](fpcap::Packet& p) { return reader.nextPacket(p); },
                              FRITZBOX);
        EXPECT_TRUE(reader.isExhausted());
    }
    SCOPED_TRACE("getReader");
    const auto reader = fpcap::Reader::getReader(filepath);
    expectFritzboxPackets([&](fpcap::Packet& p) { return reader->readNextPacket(p); },
                          FRITZBOX);
}

// zstd frame of a big-endian modified pcap with one 4 byte packet DE AD BE EF
const std::vector<uint8_t> ZSTD_BIG_ENDIAN{
    0x28, 0xB5, 0x2F, 0xFD, 0x24, 0x34, 0x7D, 0x01, 0x00, 0x64, 0x02, 0xA1,
    0xB2, 0xCD, 0x34, 0x00, 0x02, 0x00, 0x04, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x65, 0x65, 0x53, 0xF1, 0x00, 0x00, 0x01, 0xE2, 0x40, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE,
    0xEF, 0x02, 0x00, 0x7E, 0x8A, 0x55, 0x80, 0x23, 0x58, 0xDD, 0xA3, 0x3C};

template <typename TNextPacket>
void expectZstdPacket(TNextPacket nextPacket) {
    constexpr uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    fpcap::Packet packet;
    ASSERT_TRUE(nextPacket(packet));
    EXPECT_EQ(packet.timestampSeconds, 1700000000u);
    EXPECT_EQ(packet.timestampMicroseconds, 123456u);
    EXPECT_EQ(packet.captureLength, 4u);
    EXPECT_EQ(packet.length, 4u);
    EXPECT_EQ(packet.dataLinkType, fpcap::DLT_RAW);
    EXPECT_EQ(std::memcmp(packet.data, data, sizeof(data)), 0);
    EXPECT_FALSE(nextPacket(packet));
}
} // namespace

TEST(ModifiedPcapReader, NativeTimestampMicroseconds) {
    expectFritzboxPackets(FRITZBOX);
}

TEST(ByteSwappedModifiedPcapReader, MatchesNative) {
    const TempFile swapped{fpcap::test::byteSwappedCopy(FRITZBOX, 24)};
    expectFritzboxPackets(swapped.path());
}

TEST(ByteSwappedModifiedPcapReader, Zstd) {
    const TempFile file{ZSTD_BIG_ENDIAN};
    fpcap::PacketReader packetReader{file.path()};
    expectZstdPacket([&](fpcap::Packet& p) { return packetReader.nextPacket(p); });
    const auto reader = fpcap::Reader::getReader(file.path());
    expectZstdPacket([&](fpcap::Packet& p) { return reader->readNextPacket(p); });
}

TEST(ModifiedPcapParser, FileHeaderByteSwapped) {
    uint8_t data[24] = {};
    putSwapped32(data, 0, fpcap::MODIFIED_PCAP);
    putSwapped16(data, 4, 2);
    putSwapped16(data, 6, 4);
    putSwapped32(data, 8, static_cast<uint32_t>(-16));
    putSwapped32(data, 12, 6);
    putSwapped32(data, 16, 65535);
    putSwapped32(data, 20, 101);
    fpcap::modified_pcap::FileHeader fh;
    fpcap::modified_pcap::ModifiedPcapParser::readFileHeader(data, fh);
    EXPECT_TRUE(fh.byteSwapped);
    EXPECT_EQ(fh.majorVersion, 2);
    EXPECT_EQ(fh.minorVersion, 4);
    EXPECT_EQ(fh.thiszone, -16);
    EXPECT_EQ(fh.sigfigs, 6u);
    EXPECT_EQ(fh.snapLength, 65535u);
    EXPECT_EQ(fh.linkType, 101u);
}

TEST(ModifiedPcapParser, PacketRecordByteSwapped) {
    uint8_t data[25] = {};
    for (uint32_t field = 0; field < 5; ++field) {
        putSwapped32(data, field * 4, field + 1);
    }
    putSwapped16(data, 20, 0x0800);
    data[22] = 7;
    fpcap::modified_pcap::PacketRecord pr;
    fpcap::modified_pcap::ModifiedPcapParser::readPacketRecord(data, pr, true);
    EXPECT_EQ(pr.timestampSeconds, 1u);
    EXPECT_EQ(pr.timestampSubSeconds, 2u);
    EXPECT_EQ(pr.captureLength, 3u);
    EXPECT_EQ(pr.length, 4u);
    EXPECT_EQ(pr.interfaceIndex, 5u);
    EXPECT_EQ(pr.protocol, 0x0800);
    EXPECT_EQ(pr.packetType, 7);
    EXPECT_EQ(pr.data, &data[24]);
}
