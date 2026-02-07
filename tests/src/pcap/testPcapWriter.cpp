#include <gtest/gtest.h>

#include <fpcap/pcap/PcapWriter.hpp>
#include <fpcap/pcap/PcapReader.hpp>
#include <fpcap/Constants.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>

namespace {
std::string createTempFilename() {
    auto path = std::filesystem::temp_directory_path() / "fpcap_test_XXXXXX.pcap";
    std::string result = path.string();
    // Make unique by adding random suffix
    result = std::filesystem::temp_directory_path() /
             ("fpcap_test_" + std::to_string(std::rand()) + ".pcap");
    return result;
}

void removeFile(const std::string& filepath) {
    std::filesystem::remove(filepath);
}
}

TEST(PcapWriter, ConstructorCreatesFile) {
    const std::string tempFile = createTempFilename();
    {
        fpcap::pcap::StreamPcapWriter writer{tempFile, false};
    }
    EXPECT_TRUE(std::filesystem::exists(tempFile));
    EXPECT_GT(std::filesystem::file_size(tempFile), 0u);
    removeFile(tempFile);
}

TEST(PcapWriter, WritesValidPcapHeader) {
    std::string tempFile = createTempFilename();
    {
        fpcap::pcap::StreamPcapWriter writer{tempFile, false};
    }

    // Read and verify magic number
    std::ifstream file(tempFile, std::ios::binary);
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    EXPECT_EQ(magic, fpcap::PCAP_MICROSECONDS);

    removeFile(tempFile);
}

TEST(PcapWriter, WritePacket) {
    const std::string tempFile = createTempFilename();

    // Create a simple packet
    const uint8_t packetData[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    fpcap::Packet packet;
    packet.timestampSeconds = 1234567890;
    packet.timestampMicroseconds = 123456;
    packet.captureLength = sizeof(packetData);
    packet.length = sizeof(packetData);
    packet.data = packetData;

    {
        fpcap::pcap::StreamPcapWriter writer{tempFile, false};
        writer.write(packet);
    }

    // Verify file size: 24 (header) + 16 (packet header) + 6 (data) = 46 bytes
    EXPECT_EQ(std::filesystem::file_size(tempFile), 46u);

    removeFile(tempFile);
}

TEST(PcapWriter, RoundtripReadWrite) {
    std::string tempFile = createTempFilename();

    // Create test packets
    uint8_t data1[] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t data2[] = {0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34};

    fpcap::Packet writePacket1;
    writePacket1.timestampSeconds = 100;
    writePacket1.timestampMicroseconds = 200;
    writePacket1.captureLength = sizeof(data1);
    writePacket1.length = sizeof(data1);
    writePacket1.data = data1;

    fpcap::Packet writePacket2;
    writePacket2.timestampSeconds = 101;
    writePacket2.timestampMicroseconds = 300;
    writePacket2.captureLength = sizeof(data2);
    writePacket2.length = sizeof(data2);
    writePacket2.data = data2;

    {
        fpcap::pcap::StreamPcapWriter writer{tempFile, false};
        writer.write(writePacket1);
        writer.write(writePacket2);
    }

    // Read back and verify
    fpcap::pcap::MMPcapReader reader{tempFile};
    fpcap::Packet readPacket;
    uint64_t count = 0;

    while (!reader.isExhausted()) {
        if (reader.readNextPacket(readPacket)) {
            if (count == 0) {
                EXPECT_EQ(readPacket.timestampSeconds, 100u);
                EXPECT_EQ(readPacket.timestampMicroseconds, 200u);
                EXPECT_EQ(readPacket.captureLength, 4u);
            } else if (count == 1) {
                EXPECT_EQ(readPacket.timestampSeconds, 101u);
                EXPECT_EQ(readPacket.timestampMicroseconds, 300u);
                EXPECT_EQ(readPacket.captureLength, 6u);
            }
            ++count;
        }
    }
    ASSERT_EQ(count, 2u);

    removeFile(tempFile);
}

TEST(PcapWriter, AppendModeNewFile) {
    const std::string tempFile = createTempFilename();

    // Remove file if exists
    removeFile(tempFile);

    {
        // Append mode on non-existent file should write header
        fpcap::pcap::StreamPcapWriter writer{tempFile, true};
    }

    // Should have header (24 bytes)
    EXPECT_EQ(std::filesystem::file_size(tempFile), 24u);

    removeFile(tempFile);
}

TEST(PcapWriter, AppendModeExistingFile) {
    std::string tempFile = createTempFilename();

    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    fpcap::Packet packet;
    packet.timestampSeconds = 1;
    packet.timestampMicroseconds = 2;
    packet.captureLength = sizeof(data);
    packet.length = sizeof(data);
    packet.data = data;

    // Write first packet
    {
        fpcap::pcap::StreamPcapWriter writer{tempFile, false};
        writer.write(packet);
    }
    auto sizeAfterFirst = std::filesystem::file_size(tempFile);

    // Append second packet
    {
        fpcap::pcap::StreamPcapWriter writer{tempFile, true};
        writer.write(packet);
    }
    auto sizeAfterSecond = std::filesystem::file_size(tempFile);

    // Should have added packet header (16) + data (4) = 20 bytes, NOT another file header
    EXPECT_EQ(sizeAfterSecond, sizeAfterFirst + 20u);

    // Verify we can read both packets
    fpcap::pcap::MMPcapReader reader{tempFile};
    fpcap::Packet readPacket;
    uint64_t count = 0;
    while (!reader.isExhausted()) {
        if (reader.readNextPacket(readPacket)) {
            ++count;
        }
    }
    ASSERT_EQ(count, 2u);

    removeFile(tempFile);
}
