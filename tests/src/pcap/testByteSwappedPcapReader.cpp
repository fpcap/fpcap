#include <gtest/gtest.h>

#include "../TestFiles.hpp"

#include <fpcap/PacketReader.hpp>

#include <cstring>
#include <string>

namespace {
void expectSameAsNative(const std::string& nativePath, const bool mmap) {
    const fpcap::test::TempFile swapped{fpcap::test::byteSwappedCopy(nativePath, 16)};
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
} // namespace

TEST(ByteSwappedPcapReader, MMapMatchesNative) {
    expectSameAsNative("tracefiles/example.pcap", true);
}

TEST(ByteSwappedPcapReader, FReadMatchesNative) {
    expectSameAsNative("tracefiles/example.pcap", false);
}
