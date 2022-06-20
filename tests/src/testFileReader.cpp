#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>
#include <mmpr/mmpr.h>

TEST(FileReader, GetReader) {
    for (auto& p : boost::filesystem::directory_iterator("tracefiles/")) {
        auto reader = mmpr::FileReader::getReader(p.path().string());
        reader->open();

        mmpr::Packet packet;
        uint64_t processedPackets{0};
        while (!reader->isExhausted()) {
            if (reader->readNextPacket(packet)) {
                ++processedPackets;
            }
        }
        ASSERT_GT(processedPackets, 0) << "file: " << p.path().string();
    }
}