#include "gtest/gtest.h"

#include "mmpr/filesystem/reading/MMapFileReader.hpp"

TEST(MMapFileReader, ConstructorEmptyFilepath) {
    EXPECT_THROW(mmpr::MMapFileReader{""}, std::runtime_error);
}

TEST(MMapFileReader, ConstructorNonExistingFilepath) {
    EXPECT_THROW(mmpr::MMapFileReader{"missing-file"}, std::runtime_error);
}
