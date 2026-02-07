#include <gtest/gtest.h>

#include <fpcap/PacketIterator.hpp>
#include <fpcap/PacketReader.hpp>
#include <fpcap/filesystem/Reader.hpp>

#include <iterator>

static_assert(std::input_iterator<fpcap::PacketIterator>);

// PacketReader range-for tests

TEST(PacketIterator, PacketReaderPcap) {
    fpcap::PacketReader reader{"tracefiles/example.pcap"};
    uint64_t count = 0;
    for (const auto& packet : reader) {
        ASSERT_EQ(packet.dataLinkType, 1);
        ++count;
    }
    ASSERT_EQ(count, 4631);
}

TEST(PacketIterator, PacketReaderPcapNg) {
    fpcap::PacketReader reader{"tracefiles/pcapng-example.pcapng"};
    uint64_t count = 0;
    for (const auto& packet : reader) {
        (void)packet;
        ++count;
    }
    ASSERT_EQ(count, 159);
}

// Reader (unique_ptr) range-for tests

TEST(PacketIterator, ReaderPcap) {
    auto reader = fpcap::Reader::getReader("tracefiles/example.pcap");
    uint64_t count = 0;
    for (const auto& packet : *reader) {
        ASSERT_EQ(packet.dataLinkType, 1);
        ++count;
    }
    ASSERT_EQ(count, 4631);
}

TEST(PacketIterator, ReaderPcapNg) {
    auto reader = fpcap::Reader::getReader("tracefiles/pcapng-example.pcapng");
    uint64_t count = 0;
    for (const auto& packet : *reader) {
        (void)packet;
        ++count;
    }
    ASSERT_EQ(count, 159);
}

// Edge case: exhausted reader yields 0 packets

TEST(PacketIterator, ExhaustedPacketReader) {
    fpcap::PacketReader reader{"tracefiles/example.pcap"};
    fpcap::Packet packet;
    while (reader.nextPacket(packet)) {
    }

    uint64_t count = 0;
    for (const auto& p : reader) {
        (void)p;
        ++count;
    }
    ASSERT_EQ(count, 0);
}

TEST(PacketIterator, ExhaustedReader) {
    auto reader = fpcap::Reader::getReader("tracefiles/example.pcap");
    fpcap::Packet packet;
    while (reader->readNextPacket(packet)) {
    }

    uint64_t count = 0;
    for (const auto& p : *reader) {
        (void)p;
        ++count;
    }
    ASSERT_EQ(count, 0);
}

// Consistency: iterator count matches manual while-loop count

TEST(PacketIterator, ConsistencyWithWhileLoop) {
    // Manual while-loop count
    fpcap::PacketReader whileReader{"tracefiles/pcapng-example.pcapng"};
    fpcap::Packet packet;
    uint64_t whileCount = 0;
    while (whileReader.nextPacket(packet)) {
        ++whileCount;
    }

    // Range-for count
    fpcap::PacketReader forReader{"tracefiles/pcapng-example.pcapng"};
    uint64_t forCount = 0;
    for (const auto& p : forReader) {
        (void)p;
        ++forCount;
    }

    ASSERT_EQ(forCount, whileCount);
}
