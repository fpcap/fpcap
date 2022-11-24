#include "gtest/gtest.h"

#include "mmpr/filesystem/reading/ZstdFileReader.hpp"

TEST(ZstdFileReader, ConstructorEmptyFilepath) {
    EXPECT_THROW(mmpr::ZstdFileReader{""}, std::runtime_error);
}

TEST(ZstdFileReader, ConstructorNonExistingFilepath) {
    EXPECT_THROW(mmpr::ZstdFileReader{"missing-file"}, std::runtime_error);
}
