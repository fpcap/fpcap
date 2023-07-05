#ifdef FPCAP_USE_ZSTD

#include "gtest/gtest.h"

#include "fpcap/pcapng/PcapNgReader.hpp"

TEST(ZstdPcapNgReader, ConstructorSimple) {
    {
        fpcap::ZstdPcapNgReader reader{"tracefiles/pcapng-example.pcapng.zst"};
        EXPECT_EQ(reader.getFilepath(), "tracefiles/pcapng-example.pcapng.zst")
            << "Hint: make sure to execute unit tests from root directory";
    }
    {
        fpcap::ZstdPcapNgReader reader{"tracefiles/pcapng-example.pcapng.zstd"};
        EXPECT_EQ(reader.getFilepath(), "tracefiles/pcapng-example.pcapng.zstd")
            << "Hint: make sure to execute unit tests from root directory";
    }
}

TEST(ZstdPcapNgReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::ZstdPcapNgReader{"missing-file"}, std::runtime_error);
}

TEST(ZstdPcapNgReader, ConstructorNonZstdFile) {
    EXPECT_THROW(fpcap::ZstdPcapNgReader{"tracefiles/pcapng-example.pcapng"},
                 std::runtime_error);
}

TEST(ZstdPcapNgReader, FaultyConstructor) {
    EXPECT_THROW(fpcap::ZstdPcapNgReader{nullptr}, std::logic_error);
    EXPECT_THROW(fpcap::ZstdPcapNgReader{""}, std::runtime_error);
}

TEST(ZstdPcapNgReader, PcapNgExample) {
    {
        // Standard Ethernet
        fpcap::ZstdPcapNgReader reader{"tracefiles/pcapng-example.pcapng.zst"};
        fpcap::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_TRUE(reader.getDataLinkType() == 1 /* Ethernet */ ||
                            reader.getDataLinkType() == 113 /* Linux SLL */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 159);
    }
}

#endif
