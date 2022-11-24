#include "gtest/gtest.h"

#include "mmpr/filesystem/reading/FReadFileReader.hpp"

TEST(FReadFileReader, ConstructorEmptyFilepath) {
    EXPECT_THROW(mmpr::FReadFileReader{""}, std::runtime_error);
}

TEST(FReadFileReader, ConstructorNonExistingFilepath) {
    EXPECT_THROW(mmpr::FReadFileReader{"missing-file"}, std::runtime_error);
}
