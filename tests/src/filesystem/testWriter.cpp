#include <gtest/gtest.h>

#include <fpcap/filesystem/Writer.hpp>

#include <cstdlib>
#include <filesystem>
#include <string>

TEST(fpcap, GetWriter) {
    const std::string tempFile = (std::filesystem::temp_directory_path() /
            ("fpcap_test_" + std::to_string(std::rand()) + ".tmp"))
        .string();
    ASSERT_NE(nullptr, fpcap::Writer::getWriter(tempFile));
}

TEST(fpcap, GetWriterEmptyFilepath) {
    EXPECT_THROW(fpcap::Writer::getWriter(""), std::runtime_error);
}
