#include "gtest/gtest.h"

#include "mmpr/pcap/StreamPcapReader.h"

TEST(StreamPcapReader, ConstructorSimple) {
    mmpr::StreamPcapReader reader{"tracefiles/example.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(StreamPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::StreamPcapReader{"missing-file"}, std::runtime_error);
}

TEST(StreamPcapReader, FaultyConstructor) {
    EXPECT_THROW(mmpr::StreamPcapReader{nullptr}, std::logic_error);
    EXPECT_THROW(mmpr::StreamPcapReader{""}, std::runtime_error);
}

TEST(StreamPcapReader, DLT) {
    {
        // Standard Ethernet
        mmpr::StreamPcapReader reader{"tracefiles/example.pcap"};
        reader.open();
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
        mmpr::StreamPcapReader reader{"tracefiles/linux-cooked-unsw-nb15.pcap"};
        reader.open();
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