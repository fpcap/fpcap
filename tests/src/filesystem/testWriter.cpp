#include <gtest/gtest.h>

#include <fpcap/filesystem/Writer.hpp>

TEST(fpcap, GetWriter) {
    // TODO replace with something platform independent
    ASSERT_NE(nullptr,fpcap::Writer::getWriter(std::tmpnam(nullptr)));
}

TEST(fpcap, GetWriterEmptyFilepath) {
    EXPECT_THROW(fpcap::Writer::getWriter(""), std::runtime_error);
}
