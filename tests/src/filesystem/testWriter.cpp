#include <gtest/gtest.h>

#include <fpcap/filesystem/Writer.hpp>

#include <cstdlib>
#include <filesystem>
#include <string>

TEST(fpcap, GetWriter) {
    const std::string tempFile = (std::filesystem::temp_directory_path() /
            ("fpcap_test_" + std::to_string(std::rand()) + ".tmp"))
        .string();
    {
        const auto writer = fpcap::Writer::getWriter(tempFile);
        EXPECT_NE(nullptr, writer);
    }
    EXPECT_TRUE(std::filesystem::exists(tempFile));
    std::filesystem::remove(tempFile);
}

TEST(fpcap, GetWriterEmptyFilepath) {
    EXPECT_THROW(fpcap::Writer::getWriter(""), std::runtime_error);
}
