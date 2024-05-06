#include "gtest/gtest.h"

#include "fpcap/fpcap.hpp"

#include <fpcap/pcap/PcapWriter.hpp>

TEST(fpcap, GetReader) {
    ASSERT_NE(nullptr, fpcap::Reader::getReader("tracefiles/example.pcap"));
}

TEST(fpcap, GetReaderEmptyFilepath) {
    EXPECT_THROW(fpcap::Reader::getReader(""), std::runtime_error);
}

TEST(fpcap, GetReaderNonExistingFilepath) {
    EXPECT_THROW(fpcap::Reader::getReader("missing-file"), std::runtime_error);
}

TEST(fpcap, GetReaderBrokenFile) {
    EXPECT_THROW(fpcap::Reader::getReader("tracefiles/broken.pcap"), std::runtime_error);
}

TEST(fpcap, CutShortPcap) {
    auto reader = fpcap::Reader::getReader("tracefiles/RICS2021_787__fwscada_20200625_160926.pcap");

    size_t packetCount = 0;
    fpcap::Packet packet;
    while (reader->readNextPacket(packet)) {
        ++packetCount;
    }
    ASSERT_EQ(6718, packetCount);
}
