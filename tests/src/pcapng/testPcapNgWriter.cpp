#include <gtest/gtest.h>

#include <fpcap/Constants.hpp>
#include <fpcap/pcapng/PcapNgReader.hpp>
#include <fpcap/pcapng/PcapNgWriter.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>

namespace {
std::string createTempFilename() {
    return (std::filesystem::temp_directory_path() /
            ("fpcap_test_" + std::to_string(std::rand()) + ".pcapng"))
        .string();
}

void removeFile(const std::string& filepath) {
    std::filesystem::remove(filepath);
}
} // namespace

TEST(PcapNgWriter, ConstructorCreatesFile) {
    const std::string tempFile = createTempFilename();
    {
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, false};
    }
    EXPECT_TRUE(std::filesystem::exists(tempFile));
    EXPECT_GT(std::filesystem::file_size(tempFile), 0u);
    removeFile(tempFile);
}

TEST(PcapNgWriter, WritesValidSHB) {
    std::string tempFile = createTempFilename();
    {
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, false};
    }

    {
        std::ifstream file(tempFile, std::ios::binary);

        uint32_t blockType = 0;
        file.read(reinterpret_cast<char*>(&blockType), 4);
        EXPECT_EQ(blockType, fpcap::PCAPNG);

        uint32_t blockTotalLength = 0;
        file.read(reinterpret_cast<char*>(&blockTotalLength), 4);
        EXPECT_EQ(blockTotalLength, 28u);

        uint32_t byteOrderMagic = 0;
        file.read(reinterpret_cast<char*>(&byteOrderMagic), 4);
        EXPECT_EQ(byteOrderMagic, 0x1A2B3C4Du);

        uint16_t majorVersion = 0;
        file.read(reinterpret_cast<char*>(&majorVersion), 2);
        EXPECT_EQ(majorVersion, 1u);

        uint16_t minorVersion = 0;
        file.read(reinterpret_cast<char*>(&minorVersion), 2);
        EXPECT_EQ(minorVersion, 0u);

        int64_t sectionLength = 0;
        file.read(reinterpret_cast<char*>(&sectionLength), 8);
        EXPECT_EQ(sectionLength, -1);

        uint32_t blockTotalLength2 = 0;
        file.read(reinterpret_cast<char*>(&blockTotalLength2), 4);
        EXPECT_EQ(blockTotalLength2, 28u);
    }

    removeFile(tempFile);
}

TEST(PcapNgWriter, WritesValidIDB) {
    std::string tempFile = createTempFilename();
    {
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, false};
    }

    {
        std::ifstream file(tempFile, std::ios::binary);
        // Skip SHB (28 bytes)
        file.seekg(28);

        uint32_t blockType = 0;
        file.read(reinterpret_cast<char*>(&blockType), 4);
        EXPECT_EQ(blockType, 1u);

        uint32_t blockTotalLength = 0;
        file.read(reinterpret_cast<char*>(&blockTotalLength), 4);
        EXPECT_EQ(blockTotalLength, 20u);

        uint16_t linkType = 0;
        file.read(reinterpret_cast<char*>(&linkType), 2);
        EXPECT_EQ(linkType, 1u);

        uint16_t reserved = 0xFFFF;
        file.read(reinterpret_cast<char*>(&reserved), 2);
        EXPECT_EQ(reserved, 0u);

        uint32_t snapLen = 0;
        file.read(reinterpret_cast<char*>(&snapLen), 4);
        EXPECT_EQ(snapLen, 0u);

        uint32_t blockTotalLength2 = 0;
        file.read(reinterpret_cast<char*>(&blockTotalLength2), 4);
        EXPECT_EQ(blockTotalLength2, 20u);
    }

    removeFile(tempFile);
}

TEST(PcapNgWriter, WritePacket) {
    const std::string tempFile = createTempFilename();

    const uint8_t packetData[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    fpcap::Packet packet;
    packet.timestampSeconds = 1234567890;
    packet.timestampMicroseconds = 123456;
    packet.captureLength = sizeof(packetData);
    packet.length = sizeof(packetData);
    packet.data = packetData;

    {
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, false};
        writer.write(packet);
    }

    // SHB(28) + IDB(20) + EPB(32 + 6 data + 2 padding) = 88
    EXPECT_EQ(std::filesystem::file_size(tempFile), 88u);

    removeFile(tempFile);
}

TEST(PcapNgWriter, WritePacketAligned) {
    const std::string tempFile = createTempFilename();

    const uint8_t packetData[] = {0x00, 0x01, 0x02, 0x03};
    fpcap::Packet packet;
    packet.timestampSeconds = 1;
    packet.timestampMicroseconds = 2;
    packet.captureLength = sizeof(packetData);
    packet.length = sizeof(packetData);
    packet.data = packetData;

    {
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, false};
        writer.write(packet);
    }

    // SHB(28) + IDB(20) + EPB(32 + 4 data + 0 padding) = 84
    EXPECT_EQ(std::filesystem::file_size(tempFile), 84u);

    removeFile(tempFile);
}

TEST(PcapNgWriter, RoundtripReadWrite) {
    std::string tempFile = createTempFilename();

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
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, false};
        writer.write(writePacket1);
        writer.write(writePacket2);
    }

    // Read back and verify
    {
        fpcap::pcapng::MMPcapNgReader reader{tempFile};
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
    }

    removeFile(tempFile);
}

TEST(PcapNgWriter, AppendModeNewFile) {
    const std::string tempFile = createTempFilename();

    removeFile(tempFile);

    {
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, true};
    }

    // Should have SHB(28) + IDB(20) = 48 bytes
    EXPECT_EQ(std::filesystem::file_size(tempFile), 48u);

    removeFile(tempFile);
}

TEST(PcapNgWriter, AppendModeExistingFile) {
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
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, false};
        writer.write(packet);
    }
    auto sizeAfterFirst = std::filesystem::file_size(tempFile);

    // Append second packet
    {
        fpcap::pcapng::StreamPcapNgWriter writer{tempFile, true};
        writer.write(packet);
    }
    auto sizeAfterSecond = std::filesystem::file_size(tempFile);

    // Should have added EPB(32 + 4 data) = 36 bytes, NOT another SHB/IDB
    EXPECT_EQ(sizeAfterSecond, sizeAfterFirst + 36u);

    // Verify we can read both packets
    {
        fpcap::pcapng::MMPcapNgReader reader{tempFile};
        fpcap::Packet readPacket;
        uint64_t count = 0;
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(readPacket)) {
                ++count;
            }
        }
        ASSERT_EQ(count, 2u);
    }

    removeFile(tempFile);
}
