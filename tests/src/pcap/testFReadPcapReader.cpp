#include "gtest/gtest.h"

#include "mmpr/pcap/PcapReader.hpp"

TEST(FReadPcapReader, ConstructorSimple) {
    mmpr::FReadPcapReader reader{"tracefiles/example.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(FReadPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::FReadPcapReader{"missing-file"}, std::runtime_error);
}

#if __linux__
// TODO this behaves strangely on Windows
TEST(FReadPcapReader, FaultyConstructorNullptr) {
    EXPECT_THROW(mmpr::FReadPcapReader{nullptr}, std::logic_error);
}
#endif

TEST(FReadPcapReader, FaultyConstructorEmptyFilepath) {
    EXPECT_THROW(mmpr::FReadPcapReader{""}, std::runtime_error);
}

TEST(FReadPcapReader, DLT) {
    {
        // Standard Ethernet
        mmpr::FReadPcapReader reader{"tracefiles/example.pcap"};
        mmpr::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(packet.dataLinkType, 1 /* Ethernet (10Mb) */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 4631);
    }
    {
        // Linux Cooked Capture (SLL)
        mmpr::FReadPcapReader reader{"tracefiles/linux-cooked-unsw-nb15.pcap"};
        mmpr::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(packet.dataLinkType, 113 /* Linux Cooked */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 1000);
    }
}
