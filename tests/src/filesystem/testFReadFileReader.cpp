#include <gtest/gtest.h>

#include <fpcap/filesystem/FReadFileReader.hpp>

TEST(FReadFileReader, ConstructorEmptyFilepath) {
    EXPECT_THROW(fpcap::FReadFileReader{""}, std::runtime_error);
}

TEST(FReadFileReader, ConstructorNonExistingFilepath) {
    EXPECT_THROW(fpcap::FReadFileReader{"missing-file"}, std::runtime_error);
}
