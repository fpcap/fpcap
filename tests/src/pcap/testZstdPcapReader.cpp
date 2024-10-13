#if FPCAP_USE_ZSTD
#include <gtest/gtest.h>

#include <fpcap/pcap/PcapReader.hpp>

TEST(ZstdPcapReader, ConstructorSimple) {
    fpcap::ZstdPcapReader reader{"tracefiles/example.pcap.zst"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap.zst")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(ZstdPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::ZstdPcapReader{"missing-file"}, std::runtime_error);
}

TEST(ZstdPcapReader, FaultyConstructor) {
    EXPECT_THROW(fpcap::ZstdPcapReader{nullptr}, std::logic_error);
    EXPECT_THROW(fpcap::ZstdPcapReader{""}, std::runtime_error);
}

TEST(ZstdPcapReader, DLT) {
    {
        // Standard Ethernet
        fpcap::ZstdPcapReader reader{"tracefiles/example.pcap.zst"};
        fpcap::Packet packet;
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
        fpcap::ZstdPcapReader reader{"tracefiles/linux-cooked-unsw-nb15.pcap.zst"};
        fpcap::Packet packet;
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

#endif
