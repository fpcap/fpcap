#include <gtest/gtest.h>

#include <fpcap/pcapng/PcapNgBlockParser.hpp>
#include <fpcap/pcapng/PcapNgBlockType.hpp>
#include <array>
#include <cstring>

namespace {

// Helper to create a valid Simple Packet Block in memory
// SPB format:
//   0-3: Block Type (0x00000003)
//   4-7: Block Total Length
//   8-11: Original Packet Length
//   12+: Packet Data (padded to 32 bits)
//   Last 4 bytes: Block Total Length (repeated)
std::vector<uint8_t> createSimplePacketBlock(const std::vector<uint8_t>& packetData,
                                              uint32_t originalLength) {
    // Calculate padded data length (multiple of 4)
    const uint32_t paddedDataLength =
        static_cast<uint32_t>(packetData.size()) +
        (4 - static_cast<uint32_t>(packetData.size()) % 4) % 4;
    // Block total length = 4 (type) + 4 (length) + 4 (original length) + padded data + 4 (length)
    const uint32_t blockTotalLength = 16 + paddedDataLength;

    std::vector<uint8_t> block(blockTotalLength, 0);

    // Block Type
    const uint32_t blockType = fpcap::pcapng::SIMPLE_PACKET_BLOCK;
    std::memcpy(&block[0], &blockType, 4);

    // Block Total Length
    std::memcpy(&block[4], &blockTotalLength, 4);

    // Original Packet Length
    std::memcpy(&block[8], &originalLength, 4);

    // Packet Data
    std::memcpy(&block[12], packetData.data(), packetData.size());

    // Block Total Length (repeated at end)
    std::memcpy(&block[blockTotalLength - 4], &blockTotalLength, 4);

    return block;
}

} // namespace

TEST(SimplePacketBlock, ParseBasic) {
    // Create a simple 14-byte Ethernet frame (dst MAC + src MAC + ethertype)
    std::vector<uint8_t> packetData = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC (broadcast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00                           // ethertype (IPv4)
    };

    auto block = createSimplePacketBlock(packetData, 14);

    fpcap::pcapng::SimplePacketBlock spb{};
    fpcap::pcapng::PcapNgBlockParser::readSPB(block.data(), spb);

    EXPECT_EQ(spb.blockTotalLength, 32u); // 16 + 16 (14 bytes padded to 16)
    EXPECT_EQ(spb.originalPacketLength, 14u);
    EXPECT_NE(spb.packetData, nullptr);

    // Verify packet data
    EXPECT_EQ(std::memcmp(spb.packetData, packetData.data(), packetData.size()), 0);
}

TEST(SimplePacketBlock, ParseLargePacket) {
    // Create a 1500-byte packet (typical MTU)
    std::vector<uint8_t> packetData(1500, 0xAB);

    auto block = createSimplePacketBlock(packetData, 1500);

    fpcap::pcapng::SimplePacketBlock spb{};
    fpcap::pcapng::PcapNgBlockParser::readSPB(block.data(), spb);

    EXPECT_EQ(spb.blockTotalLength, 1516u); // 16 + 1500 (already multiple of 4)
    EXPECT_EQ(spb.originalPacketLength, 1500u);
    EXPECT_NE(spb.packetData, nullptr);

    // Verify first and last bytes
    EXPECT_EQ(spb.packetData[0], 0xAB);
    EXPECT_EQ(spb.packetData[1499], 0xAB);
}

TEST(SimplePacketBlock, ParseTruncatedPacket) {
    // Test case where original length > captured length (truncated packet)
    std::vector<uint8_t> packetData(64, 0xCD); // Only captured 64 bytes
    const uint32_t originalLength = 1500;      // But original was 1500 bytes

    auto block = createSimplePacketBlock(packetData, originalLength);

    fpcap::pcapng::SimplePacketBlock spb{};
    fpcap::pcapng::PcapNgBlockParser::readSPB(block.data(), spb);

    // Captured length = blockTotalLength - 16
    const uint32_t capturedLength = spb.blockTotalLength - 16;
    EXPECT_EQ(capturedLength, 64u);
    EXPECT_EQ(spb.originalPacketLength, 1500u);
}

TEST(SimplePacketBlock, CapturedLengthCalculation) {
    // Verify captured length calculation from block total length
    std::vector<uint8_t> packetData(100, 0x00);
    auto block = createSimplePacketBlock(packetData, 100);

    fpcap::pcapng::SimplePacketBlock spb{};
    fpcap::pcapng::PcapNgBlockParser::readSPB(block.data(), spb);

    // Captured length = blockTotalLength - 16 (header + footer)
    const uint32_t capturedLength = spb.blockTotalLength - 16;
    EXPECT_EQ(capturedLength, 100u);
}
