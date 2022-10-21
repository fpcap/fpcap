#include "gtest/gtest.h"

#if __linux__

#include "mmpr/modified_pcap/ModifiedPcapReader.hpp"

TEST(MMModifiedPcapReader, ConstructorSimple) {
    mmpr::MMModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/fritzbox-ip.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(MMModifiedPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::MMModifiedPcapReader{"missing-file"}, std::runtime_error);
}

TEST(MMModifiedPcapReader, FaultyConstructor) {
    EXPECT_THROW(mmpr::MMModifiedPcapReader{nullptr}, std::logic_error);
    EXPECT_THROW(mmpr::MMModifiedPcapReader{""}, std::runtime_error);
}

TEST(MMModifiedPcapReader, DLT) {
    {
        // Standard Ethernet
        mmpr::MMModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap"};
        mmpr::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(reader.getDataLinkType(), 101 /* Raw IP */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 5);
    }
}

#endif