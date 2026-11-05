#include <gtest/gtest.h>

#include <fpcap/Constants.hpp>
#include <fpcap/pcap/PcapParser.hpp>

#include <array>
#include <cstring>

namespace {
std::array<uint8_t, 24> makeFileHeader(const uint32_t linkTypeField) {
    std::array<uint8_t, 24> data{};
    const uint32_t magic = fpcap::PCAP_MICROSECONDS;
    std::memcpy(&data[0], &magic, sizeof(magic));
    std::memcpy(&data[20], &linkTypeField, sizeof(linkTypeField));
    return data;
}
} // namespace

TEST(PcapParser, FileHeaderWithoutFcs) {
    const auto data = makeFileHeader(1);
    fpcap::pcap::FileHeader fh;
    fpcap::pcap::PcapParser::readFileHeader(data.data(), fh);
    EXPECT_EQ(fh.dataLinkType, 1);
    EXPECT_FALSE(fh.fcsLengthPresent);
    EXPECT_EQ(fh.fcsLength, 0);
}

TEST(PcapParser, FileHeaderWithFcs) {
    // FCS len 2 (4-octet Ethernet FCS), P bit set, R bit set and ignored
    const auto data = makeFileHeader(0x2C000001);
    fpcap::pcap::FileHeader fh;
    fpcap::pcap::PcapParser::readFileHeader(data.data(), fh);
    EXPECT_EQ(fh.dataLinkType, 1);
    EXPECT_TRUE(fh.fcsLengthPresent);
    EXPECT_EQ(fh.fcsLength, 2);
}

TEST(PcapParser, FileHeaderWithMaxFcsLength) {
    const auto data = makeFileHeader(0xF4000071);
    fpcap::pcap::FileHeader fh;
    fpcap::pcap::PcapParser::readFileHeader(data.data(), fh);
    EXPECT_EQ(fh.dataLinkType, 113);
    EXPECT_TRUE(fh.fcsLengthPresent);
    EXPECT_EQ(fh.fcsLength, 15);
}

TEST(PcapParser, FileHeaderIgnoresRBit) {
    const auto data = makeFileHeader(0x08000001);
    fpcap::pcap::FileHeader fh;
    fpcap::pcap::PcapParser::readFileHeader(data.data(), fh);
    EXPECT_EQ(fh.dataLinkType, 1);
    EXPECT_FALSE(fh.fcsLengthPresent);
}

TEST(PcapParser, FileHeaderIgnoresReservedBits) {
    const auto data = makeFileHeader(0x03FF0001);
    fpcap::pcap::FileHeader fh;
    fpcap::pcap::PcapParser::readFileHeader(data.data(), fh);
    EXPECT_EQ(fh.dataLinkType, 1);
    EXPECT_FALSE(fh.fcsLengthPresent);
    EXPECT_EQ(fh.fcsLength, 0);
}

TEST(PcapParser, FileHeaderByteSwapped) {
    // Header written by a host of the opposite byte order, FCS len 2 with P bit set
    std::array<uint8_t, 24> data{};
    const uint8_t magic[] = {0xA1, 0xB2, 0x3C, 0x4D};
    const uint8_t version[] = {0x00, 0x02, 0x00, 0x04};
    const uint8_t snapLength[] = {0x00, 0x00, 0xFF, 0xFF};
    const uint8_t linkTypeField[] = {0x24, 0x00, 0x00, 0x71};
    std::memcpy(&data[0], magic, 4);
    std::memcpy(&data[4], version, 4);
    std::memcpy(&data[16], snapLength, 4);
    std::memcpy(&data[20], linkTypeField, 4);

    fpcap::pcap::FileHeader fh;
    fpcap::pcap::PcapParser::readFileHeader(data.data(), fh);
    EXPECT_TRUE(fh.byteSwapped);
    EXPECT_EQ(fh.timestampFormat, fpcap::pcap::FileHeader::NANOSECONDS);
    EXPECT_EQ(fh.majorVersion, 2);
    EXPECT_EQ(fh.minorVersion, 4);
    EXPECT_EQ(fh.snapLength, 65535u);
    EXPECT_EQ(fh.dataLinkType, 113);
    EXPECT_TRUE(fh.fcsLengthPresent);
    EXPECT_EQ(fh.fcsLength, 2);
}

TEST(PcapParser, FileHeaderInvalidMagic) {
    std::array<uint8_t, 24> data{};
    fpcap::pcap::FileHeader fh;
    EXPECT_THROW(fpcap::pcap::PcapParser::readFileHeader(data.data(), fh),
                 std::runtime_error);
}

TEST(PcapParser, PacketRecordByteSwapped) {
    const uint8_t data[] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
                            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0xAB};
    fpcap::pcap::PacketRecord pr;
    fpcap::pcap::PcapParser::readPacketRecord(data, pr, true);
    EXPECT_EQ(pr.timestampSeconds, 1u);
    EXPECT_EQ(pr.timestampSubSeconds, 2u);
    EXPECT_EQ(pr.captureLength, 3u);
    EXPECT_EQ(pr.length, 4u);
    EXPECT_EQ(pr.data, &data[16]);
}
