#include <gtest/gtest.h>

#include <fpcap/filesystem/ZstdFileReader.hpp>

TEST(ZstdFileReader, ConstructorEmptyFilepath) {
    EXPECT_THROW(fpcap::ZstdFileReader{""}, std::runtime_error);
}

TEST(ZstdFileReader, ConstructorNonExistingFilepath) {
    EXPECT_THROW(fpcap::ZstdFileReader{"missing-file"}, std::runtime_error);
}
