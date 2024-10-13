#include <gtest/gtest.h>

#include <fpcap/filesystem/Reader.hpp>
#include <fpcap/filesystem/Writer.hpp>

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
    const auto reader = fpcap::Reader::getReader("tracefiles/RICS2021_787__fwscada_20200625_160926.pcap");

    size_t packetCount = 0;
    fpcap::Packet packet;
    while (reader->readNextPacket(packet)) {
        ++packetCount;
    }
    ASSERT_EQ(6718, packetCount);
}
