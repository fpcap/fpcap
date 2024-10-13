#include <gtest/gtest.h>

#include <fpcap/filesystem/MMapFileReader.hpp>

TEST(MMapFileReader, ConstructorEmptyFilepath) {
    EXPECT_THROW(fpcap::MMapFileReader{""}, std::runtime_error);
}

TEST(MMapFileReader, ConstructorNonExistingFilepath) {
    EXPECT_THROW(fpcap::MMapFileReader{"missing-file"}, std::runtime_error);
}
