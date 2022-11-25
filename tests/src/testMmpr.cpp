#include "gtest/gtest.h"

#include "mmpr/mmpr.hpp"

TEST(Mmpr, GetReader) {
    ASSERT_NE(nullptr, mmpr::Reader::getReader("tracefiles/example.pcap"));
}

TEST(Mmpr, GetReaderEmptyFilepath) {
    EXPECT_THROW(mmpr::Reader::getReader(""), std::runtime_error);
}

TEST(Mmpr, GetReaderNonExistingFilepath) {
    EXPECT_THROW(mmpr::Reader::getReader("missing-file"), std::runtime_error);
}

TEST(Mmpr, GetReaderBrokenFile) {
    EXPECT_THROW(mmpr::Reader::getReader("tracefiles/broken.pcap"), std::runtime_error);
}

TEST(Mmpr, GetWriter) {
    // TODO replace with something platform independent
    ASSERT_NE(nullptr,mmpr::Writer::getWriter(std::tmpnam(nullptr)));
}

TEST(Mmpr, GetWriterEmptyFilepath) {
    EXPECT_THROW(mmpr::Writer::getWriter(""), std::runtime_error);
}
