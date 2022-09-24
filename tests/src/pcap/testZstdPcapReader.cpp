#include "gtest/gtest.h"

#include "mmpr/pcap/PcapReader.h"

TEST(ZstdPcapReader, ConstructorSimple) {
    mmpr::ZstdPcapReader reader{"tracefiles/example.pcap.zst"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap.zst")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(ZstdPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::ZstdPcapReader{"missing-file"}, std::runtime_error);
}

TEST(ZstdPcapReader, FaultyConstructor) {
    EXPECT_THROW(mmpr::ZstdPcapReader{nullptr}, std::logic_error);
    EXPECT_THROW(mmpr::ZstdPcapReader{""}, std::runtime_error);
}

TEST(ZstdPcapReader, DLT) {
    {
        // Standard Ethernet
        mmpr::ZstdPcapReader reader{"tracefiles/example.pcap.zst"};
        mmpr::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(reader.getDataLinkType(), 1 /* Ethernet (10Mb) */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 4631);
    }
    {
        // Linux Cooked Capture (SLL)
        mmpr::ZstdPcapReader reader{"tracefiles/linux-cooked-unsw-nb15.pcap.zst"};
        mmpr::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(reader.getDataLinkType(), 113 /* Linux Cooked */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 1000);
    }
}