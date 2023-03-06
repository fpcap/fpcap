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

#if __linux__
// TODO this behaves strangely on Windows
TEST(FReadModifiedPcapReader, FaultyConstructorNullptr) {
    EXPECT_THROW(mmpr::FReadModifiedPcapReader{nullptr}, std::logic_error);
}
#endif

TEST(FReadModifiedPcapReader, FaultyConstructorEmptyFilepath) {
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
                ASSERT_EQ(packet.dataLinkType, 101 /* Raw IP */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 5);
    }
}
