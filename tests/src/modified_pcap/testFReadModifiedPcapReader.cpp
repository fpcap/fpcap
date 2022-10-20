#include "gtest/gtest.h"

#include "mmpr/modified_pcap/ModifiedPcapReader.hpp"

TEST(FReadModifiedPcapReader, ConstructorSimple) {
    mmpr::FReadModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/fritzbox-ip.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(FReadModifiedPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::FReadModifiedPcapReader{"missing-file"}, std::runtime_error);
}

TEST(FReadModifiedPcapReader, FaultyConstructor) {
    EXPECT_THROW(mmpr::FReadModifiedPcapReader{nullptr}, std::logic_error);
    EXPECT_THROW(mmpr::FReadModifiedPcapReader{""}, std::runtime_error);
}

TEST(FReadModifiedPcapReader, DLT) {
    {
        // Standard Ethernet
        mmpr::FReadModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap"};
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