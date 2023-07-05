#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "fpcap/filesystem/reading/FileReader.hpp"
#include <filesystem>
#include <iostream>

class FileReaderMock : public fpcap::FileReader {
public:
    FileReaderMock(const std::string& filepath) : fpcap::FileReader(filepath) {}

    MOCK_METHOD(const uint8_t*, data, (), (const, override));
};

TEST(FileReader, Constructor) {
    FileReaderMock reader{"tracefiles/example.pcap"};
}

TEST(FileReader, ConstructorEmptyFilepath) {
    EXPECT_THROW(FileReaderMock{""}, std::runtime_error);
}

TEST(FileReader, ConstructorNonExistingFilepath) {
    EXPECT_THROW(FileReaderMock{"missing-file"}, std::runtime_error);
}

// TODO list files to test explicitly
TEST(FileReader, GetReader) {
    std::vector<std::string> files;
    for (auto& p : std::filesystem::directory_iterator("tracefiles/")) {
        std::string file = p.path().string();

#ifndef FPCAP_USE_ZSTD
        // do not include compressed files if built without decompression support
        if (file.find(".zstd") != std::string::npos ||
            file.find(".zst") != std::string::npos) {
            continue;
        }
#endif

        if (file.find("broken.pcap") != std::string::npos) {
            continue;
        }

        files.emplace_back(file);
    }

    for (const std::string& file : files) {
        std::cout << "Reading file " << file << std::endl;

        auto reader = fpcap::Reader::getReader(file);
        fpcap::Packet packet;
        uint64_t processedPackets{0};
        while (!reader->isExhausted()) {
            if (reader->readNextPacket(packet)) {
                ++processedPackets;
            }
        }
        ASSERT_GT(processedPackets, 0) << "file: " << file;
    }
}
