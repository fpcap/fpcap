#include "gtest/gtest.h"

#if FPCAP_USE_ZSTD

#include "fpcap/modified_pcap/ModifiedPcapReader.hpp"

TEST(ZstdModifiedPcapReader, ConstructorSimple) {
    fpcap::ZstdModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap.zst"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/fritzbox-ip.pcap.zst")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(ZstdModifiedPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::ZstdModifiedPcapReader{"missing-file"}, std::runtime_error);
}

TEST(ZstdModifiedPcapReader, FaultyConstructor) {
    EXPECT_THROW(fpcap::ZstdModifiedPcapReader{nullptr}, std::logic_error);
    EXPECT_THROW(fpcap::ZstdModifiedPcapReader{""}, std::runtime_error);
}

TEST(ZstdModifiedPcapReader, DLT) {
    {
        // Standard Ethernet
        fpcap::ZstdModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap.zst"};
        fpcap::Packet packet;
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
