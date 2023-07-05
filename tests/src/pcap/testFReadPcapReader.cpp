#include "gtest/gtest.h"

#include "fpcap/pcap/PcapReader.hpp"

TEST(FReadPcapReader, ConstructorSimple) {
    fpcap::FReadPcapReader reader{"tracefiles/example.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(FReadPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::FReadPcapReader{"missing-file"}, std::runtime_error);
}

#if __linux__
// TODO this behaves strangely on Windows
TEST(FReadPcapReader, FaultyConstructorNullptr) {
    EXPECT_THROW(fpcap::FReadPcapReader{nullptr}, std::logic_error);
}
#endif

TEST(FReadPcapReader, FaultyConstructorEmptyFilepath) {
    EXPECT_THROW(fpcap::FReadPcapReader{""}, std::runtime_error);
}

TEST(FReadPcapReader, DLT) {
    {
        // Standard Ethernet
        fpcap::FReadPcapReader reader{"tracefiles/example.pcap"};
        fpcap::Packet packet;
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
        fpcap::FReadPcapReader reader{"tracefiles/linux-cooked-unsw-nb15.pcap"};
        fpcap::Packet packet;
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
