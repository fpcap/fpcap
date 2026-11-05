#include <gtest/gtest.h>

#include <fpcap/PacketReader.hpp>
#include <fpcap/util.hpp>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void swap16(std::vector<char>& bytes, const size_t offset) {
    uint16_t value;
    std::memcpy(&value, &bytes[offset], sizeof(value));
    value = fpcap::util::byteSwap16(value);
    std::memcpy(&bytes[offset], &value, sizeof(value));
}

void swap32(std::vector<char>& bytes, const size_t offset) {
    uint32_t value;
    std::memcpy(&value, &bytes[offset], sizeof(value));
    value = fpcap::util::byteSwap32(value);
    std::memcpy(&bytes[offset], &value, sizeof(value));
}

// Temporary copy of a native byte order pcap as if written on the opposite byte order
class ByteSwappedCopy {
public:
    explicit ByteSwappedCopy(const std::string& filepath) {
        std::ifstream in(filepath, std::ios::binary);
        std::vector<char> bytes{std::istreambuf_iterator<char>(in), {}};
        if (bytes.size() < 24) {
            throw std::runtime_error("cannot read " + filepath);
        }
        swapAll(bytes);

        const auto* test = testing::UnitTest::GetInstance()->current_test_info();
        mPath = (std::filesystem::temp_directory_path() /
                 ("fpcap_test_" + std::string(test->name()) + "_" +
                  std::to_string(std::rand()) + ".pcap"))
                    .string();
        std::ofstream out(mPath, std::ios::binary);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }

    ~ByteSwappedCopy() { std::filesystem::remove(mPath); }

    const std::string& path() const { return mPath; }

private:
    std::string mPath;

    static void swapAll(std::vector<char>& bytes) {
        swap32(bytes, 0);
        swap16(bytes, 4);
        swap16(bytes, 6);
        for (size_t offset = 8; offset < 24; offset += 4) {
            swap32(bytes, offset);
        }
        for (size_t offset = 24; offset + 16 <= bytes.size();) {
            uint32_t captureLength;
            std::memcpy(&captureLength, &bytes[offset + 8], sizeof(captureLength));
            for (size_t field = 0; field < 16; field += 4) {
                swap32(bytes, offset + field);
            }
            offset += 16 + captureLength;
        }
    }
};

void expectSameAsNative(const std::string& nativePath, const bool mmap) {
    const ByteSwappedCopy swapped{nativePath};
    {
        fpcap::PacketReader nativeReader{nativePath, mmap};
        fpcap::PacketReader swappedReader{swapped.path(), mmap};
        fpcap::Packet nativePacket;
        fpcap::Packet swappedPacket;
        uint64_t count = 0;
        while (nativeReader.nextPacket(nativePacket)) {
            ASSERT_TRUE(swappedReader.nextPacket(swappedPacket));
            ASSERT_EQ(swappedPacket.timestampSeconds, nativePacket.timestampSeconds);
            ASSERT_EQ(swappedPacket.timestampMicroseconds,
                      nativePacket.timestampMicroseconds);
            ASSERT_EQ(swappedPacket.captureLength, nativePacket.captureLength);
            ASSERT_EQ(swappedPacket.length, nativePacket.length);
            ASSERT_EQ(swappedPacket.dataLinkType, nativePacket.dataLinkType);
            ASSERT_EQ(std::memcmp(swappedPacket.data, nativePacket.data,
                                  nativePacket.captureLength),
                      0);
            ++count;
        }
        EXPECT_TRUE(swappedReader.isExhausted());
        EXPECT_GT(count, 0u);
    }
}
} // namespace

TEST(ByteSwappedPcapReader, MMapMatchesNative) {
    expectSameAsNative("tracefiles/example.pcap", true);
}

TEST(ByteSwappedPcapReader, FReadMatchesNative) {
    expectSameAsNative("tracefiles/example.pcap", false);
}
