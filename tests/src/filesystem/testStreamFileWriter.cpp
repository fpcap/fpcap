#include <gtest/gtest.h>

#include <fpcap/filesystem/StreamFileWriter.hpp>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {
std::string createTempFilename() {
    return (std::filesystem::temp_directory_path() /
            ("fpcap_writer_test_" + std::to_string(std::rand()) + ".bin")).string();
}

void removeFile(const std::string& filepath) {
    std::filesystem::remove(filepath);
}

std::vector<uint8_t> readFileContents(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}
}

TEST(StreamFileWriter, ConstructorCreatesFile) {
    const std::string tempFile = createTempFilename();
    {
        fpcap::StreamFileWriter writer{tempFile, false};
    }
    EXPECT_TRUE(std::filesystem::exists(tempFile));
    removeFile(tempFile);
}

TEST(StreamFileWriter, WriteData) {
    std::string tempFile = createTempFilename();
    uint8_t testData[] = {0x01, 0x02, 0x03, 0x04, 0x05};

    {
        fpcap::StreamFileWriter writer{tempFile, false};
        writer.write(testData, sizeof(testData));
    }

    auto contents = readFileContents(tempFile);
    ASSERT_EQ(contents.size(), sizeof(testData));
    EXPECT_EQ(std::memcmp(contents.data(), testData, sizeof(testData)), 0);

    removeFile(tempFile);
}

TEST(StreamFileWriter, WriteMultipleTimes) {
    std::string tempFile = createTempFilename();
    uint8_t data1[] = {0xAA, 0xBB};
    uint8_t data2[] = {0xCC, 0xDD, 0xEE};

    {
        fpcap::StreamFileWriter writer{tempFile, false};
        writer.write(data1, sizeof(data1));
        writer.write(data2, sizeof(data2));
    }

    auto contents = readFileContents(tempFile);
    ASSERT_EQ(contents.size(), 5u);
    EXPECT_EQ(contents[0], 0xAA);
    EXPECT_EQ(contents[1], 0xBB);
    EXPECT_EQ(contents[2], 0xCC);
    EXPECT_EQ(contents[3], 0xDD);
    EXPECT_EQ(contents[4], 0xEE);

    removeFile(tempFile);
}

TEST(StreamFileWriter, AppendMode) {
    std::string tempFile = createTempFilename();
    uint8_t data1[] = {0x11, 0x22};
    uint8_t data2[] = {0x33, 0x44};

    // Write initial data
    {
        fpcap::StreamFileWriter writer{tempFile, false};
        writer.write(data1, sizeof(data1));
    }

    // Append more data
    {
        fpcap::StreamFileWriter writer{tempFile, true};
        writer.write(data2, sizeof(data2));
    }

    auto contents = readFileContents(tempFile);
    ASSERT_EQ(contents.size(), 4u);
    EXPECT_EQ(contents[0], 0x11);
    EXPECT_EQ(contents[1], 0x22);
    EXPECT_EQ(contents[2], 0x33);
    EXPECT_EQ(contents[3], 0x44);

    removeFile(tempFile);
}

TEST(StreamFileWriter, OverwriteMode) {
    std::string tempFile = createTempFilename();
    uint8_t data1[] = {0x11, 0x22, 0x33, 0x44};
    uint8_t data2[] = {0xAA, 0xBB};

    // Write initial data
    {
        fpcap::StreamFileWriter writer{tempFile, false};
        writer.write(data1, sizeof(data1));
    }
    EXPECT_EQ(std::filesystem::file_size(tempFile), 4u);

    // Overwrite with smaller data (not append mode)
    {
        fpcap::StreamFileWriter writer{tempFile, false};
        writer.write(data2, sizeof(data2));
    }

    auto contents = readFileContents(tempFile);
    ASSERT_EQ(contents.size(), 2u);
    EXPECT_EQ(contents[0], 0xAA);
    EXPECT_EQ(contents[1], 0xBB);

    removeFile(tempFile);
}
