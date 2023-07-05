#include "gtest/gtest.h"

#include "fpcap/fpcap.hpp"

TEST(Mmpr, GetReader) {
    ASSERT_NE(nullptr, fpcap::Reader::getReader("tracefiles/example.pcap"));
}

TEST(Mmpr, GetReaderEmptyFilepath) {
    EXPECT_THROW(fpcap::Reader::getReader(""), std::runtime_error);
}

TEST(Mmpr, GetReaderNonExistingFilepath) {
    EXPECT_THROW(fpcap::Reader::getReader("missing-file"), std::runtime_error);
}

TEST(Mmpr, GetReaderBrokenFile) {
    EXPECT_THROW(fpcap::Reader::getReader("tracefiles/broken.pcap"), std::runtime_error);
}

TEST(Mmpr, GetWriter) {
    // TODO replace with something platform independent
    ASSERT_NE(nullptr,fpcap::Writer::getWriter(std::tmpnam(nullptr)));
}

TEST(Mmpr, GetWriterEmptyFilepath) {
    EXPECT_THROW(fpcap::Writer::getWriter(""), std::runtime_error);
}

TEST(Mmpr, CutShortPcap) {
    auto reader = fpcap::Reader::getReader("tracefiles/RICS2021_787__fwscada_20200625_160926.pcap");

    size_t packetCount = 0;
    fpcap::Packet packet;
    while (reader->readNextPacket(packet)) {
        ++packetCount;
    }
    ASSERT_EQ(6718, packetCount);
}
