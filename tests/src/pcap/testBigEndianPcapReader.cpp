#include <gtest/gtest.h>

#include <fpcap/PacketReader.hpp>
#include <fpcap/filesystem/Reader.hpp>

#include <array>
#include <cstring>
#include <memory>
#include <string>

// The big-endian tracefiles were written by libpcap on s390x and contain loopback
// traffic: three pings and a TCP connection sending "hello from fpcap\n".

namespace {
struct ExpectedPacket {
    uint32_t timestampSeconds;
    uint32_t timestampMicroseconds;
    uint32_t length;
};

constexpr std::array<ExpectedPacket, 14> MICROSECONDS_PACKETS{{
    {1793883777, 572404, 98},
    {1793883777, 572411, 98},
    {1793883777, 780172, 98},
    {1793883777, 780195, 98},
    {1793883777, 986117, 98},
    {1793883777, 986130, 98},
    {1793883778, 494475, 74},
    {1793883778, 494517, 74},
    {1793883778, 494535, 66},
    {1793883778, 494629, 83},
    {1793883778, 494636, 66},
    {1793883778, 494648, 66},
    {1793883778, 494703, 66},
    {1793883778, 494725, 66},
}};

// Nanoseconds truncated to microseconds, e.g. 531013632 ns becomes 531013 us
constexpr std::array<ExpectedPacket, 14> NANOSECONDS_PACKETS{{
    {1793883782, 531013, 98},
    {1793883782, 531026, 98},
    {1793883782, 737727, 98},
    {1793883782, 737746, 98},
    {1793883782, 945348, 98},
    {1793883782, 945366, 98},
    {1793883783, 452644, 74},
    {1793883783, 452659, 74},
    {1793883783, 452670, 66},
    {1793883783, 452736, 83},
    {1793883783, 452741, 66},
    {1793883783, 452746, 66},
    {1793883783, 452797, 66},
    {1793883783, 452812, 66},
}};

constexpr size_t HELLO_PACKET_INDEX = 9;
constexpr char HELLO_PAYLOAD[] = "hello from fpcap\n";

template <typename TNextPacket>
void expectPackets(TNextPacket nextPacket,
                   const std::array<ExpectedPacket, 14>& expectedPackets) {
    fpcap::Packet packet;
    size_t index = 0;
    while (nextPacket(packet)) {
        ASSERT_LT(index, expectedPackets.size());
        const auto& expected = expectedPackets[index];
        EXPECT_EQ(packet.timestampSeconds, expected.timestampSeconds) << index;
        EXPECT_EQ(packet.timestampMicroseconds, expected.timestampMicroseconds) << index;
        EXPECT_EQ(packet.captureLength, expected.length) << index;
        EXPECT_EQ(packet.length, expected.length) << index;
        EXPECT_EQ(packet.dataLinkType, 1) << index;
        if (index == HELLO_PACKET_INDEX) {
            const size_t payloadLength = sizeof(HELLO_PAYLOAD) - 1;
            ASSERT_GE(packet.captureLength, payloadLength);
            EXPECT_EQ(std::memcmp(packet.data + packet.captureLength - payloadLength,
                                  HELLO_PAYLOAD, payloadLength),
                      0);
        }
        ++index;
    }
    EXPECT_EQ(index, expectedPackets.size());
}

void expectPacketReader(const std::string& filepath,
                        const bool mmap,
                        const std::array<ExpectedPacket, 14>& expectedPackets) {
    fpcap::PacketReader reader{filepath, mmap};
    expectPackets([&](fpcap::Packet& packet) { return reader.nextPacket(packet); },
                  expectedPackets);
    EXPECT_TRUE(reader.isExhausted());
}
} // namespace

TEST(BigEndianPcapReader, MicrosecondsMMap) {
    expectPacketReader("tracefiles/big-endian.pcap", true, MICROSECONDS_PACKETS);
}

TEST(BigEndianPcapReader, MicrosecondsFRead) {
    expectPacketReader("tracefiles/big-endian.pcap", false, MICROSECONDS_PACKETS);
}

TEST(BigEndianPcapReader, NanosecondsMMap) {
    expectPacketReader("tracefiles/big-endian-nanoseconds.pcap", true,
                       NANOSECONDS_PACKETS);
}

TEST(BigEndianPcapReader, NanosecondsFRead) {
    expectPacketReader("tracefiles/big-endian-nanoseconds.pcap", false,
                       NANOSECONDS_PACKETS);
}

TEST(BigEndianPcapReader, Zstd) {
    expectPacketReader("tracefiles/big-endian.pcap.zst", true, MICROSECONDS_PACKETS);
}

TEST(BigEndianPcapReader, GetReader) {
    for (const auto* filepath :
         {"tracefiles/big-endian.pcap", "tracefiles/big-endian.pcap.zst"}) {
        const auto reader = fpcap::Reader::getReader(filepath);
        expectPackets(
            [&](fpcap::Packet& packet) { return reader->readNextPacket(packet); },
            MICROSECONDS_PACKETS);
    }
}
