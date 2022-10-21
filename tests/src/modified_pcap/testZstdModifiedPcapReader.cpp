#include "gtest/gtest.h"

#if MMPR_USE_ZSTD

#include "mmpr/modified_pcap/ModifiedPcapReader.hpp"

TEST(ZstdModifiedPcapReader, ConstructorSimple) {
    mmpr::ZstdModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap.zst"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/fritzbox-ip.pcap.zst")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(ZstdModifiedPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::ZstdModifiedPcapReader{"missing-file"}, std::runtime_error);
}

TEST(ZstdModifiedPcapReader, FaultyConstructor) {
    EXPECT_THROW(mmpr::ZstdModifiedPcapReader{nullptr}, std::logic_error);
    EXPECT_THROW(mmpr::ZstdModifiedPcapReader{""}, std::runtime_error);
}

TEST(ZstdModifiedPcapReader, DLT) {
    {
        // Standard Ethernet
        mmpr::ZstdModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap.zst"};
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