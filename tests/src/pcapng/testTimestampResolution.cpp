#include <gtest/gtest.h>

#include <fpcap/PacketReader.hpp>
#include <fpcap/pcapng/PcapNgReader.hpp>
#include <fpcap/pcapng/PcapNgWriter.hpp>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

std::string createTempFilename() {
    return (std::filesystem::temp_directory_path() /
            ("fpcap_tsresol_test_" + std::to_string(std::rand()) + ".pcapng"))
        .string();
}

struct TempFile {
    std::string path{createTempFilename()};
    ~TempFile() { std::filesystem::remove(path); }
};

// Writes a minimal little endian PcapNG file: SHB, IDB with an if_tsresol option and a
// single EPB carrying the given raw 64 bit timestamp and 4 bytes of packet data.
void writePcapNg(const std::string& path, const uint8_t tsresol,
                 const uint64_t rawTimestamp) {
    std::vector<uint32_t> words;

    // Section Header Block
    words.insert(words.end(), {0x0A0D0D0A, 28, 0x1A2B3C4D, 0x00000001, 0xFFFFFFFF,
                               0xFFFFFFFF, 28});

    // Interface Description Block: linktype 1 (Ethernet), snaplen 0,
    // option if_tsresol (type 9, length 1, padded to 4), opt_endofopt
    words.insert(words.end(), {0x00000001, 32, 0x00000001, 0x00000000,
                               9u | 1u << 16, tsresol, 0x00000000, 32});

    // Enhanced Packet Block
    words.insert(words.end(),
                 {0x00000006, 36, 0x00000000, static_cast<uint32_t>(rawTimestamp >> 32),
                  static_cast<uint32_t>(rawTimestamp & 0xFFFFFFFF), 4, 4, 0xEFBEADDE, 36});

    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(words.data()),
               static_cast<std::streamsize>(words.size() * sizeof(uint32_t)));
}

// Only the timestamp and length fields of the returned packet may be used, its data
// pointer refers to the reader's memory mapping which is released on return.
fpcap::Packet readSinglePacket(const std::string& path) {
    fpcap::pcapng::MMPcapNgReader reader{path};
    fpcap::Packet packet;
    while (!reader.isExhausted()) {
        if (reader.readNextPacket(packet)) {
            return packet;
        }
    }
    ADD_FAILURE() << "no packet found in " << path;
    return packet;
}

} // namespace

TEST(PcapNgTimestampResolution, Microseconds) {
    const TempFile file;
    writePcapNg(file.path, 6, 1700000000ULL * 1'000'000 + 123456);

    const auto packet = readSinglePacket(file.path);
    EXPECT_EQ(packet.timestampSeconds, 1700000000u);
    EXPECT_EQ(packet.timestampMicroseconds, 123456u);
}

TEST(PcapNgTimestampResolution, NanosecondsAreConvertedToMicroseconds) {
    // Regression test: previously timestampMicroseconds contained 123456789 here
    const TempFile file;
    writePcapNg(file.path, 9, 1700000000ULL * 1'000'000'000 + 123456789);

    const auto packet = readSinglePacket(file.path);
    EXPECT_EQ(packet.timestampSeconds, 1700000000u);
    EXPECT_EQ(packet.timestampMicroseconds, 123456u);
}

TEST(PcapNgTimestampResolution, MillisecondsAreConvertedToMicroseconds) {
    const TempFile file;
    writePcapNg(file.path, 3, 1700000000ULL * 1'000 + 250);

    const auto packet = readSinglePacket(file.path);
    EXPECT_EQ(packet.timestampSeconds, 1700000000u);
    EXPECT_EQ(packet.timestampMicroseconds, 250000u);
}

TEST(PcapNgTimestampResolution, PowerOf2IsConvertedToMicroseconds) {
    const TempFile file;
    writePcapNg(file.path, 0x80 | 10, 1700000000ULL * 1024 + 512);

    const auto packet = readSinglePacket(file.path);
    EXPECT_EQ(packet.timestampSeconds, 1700000000u);
    EXPECT_EQ(packet.timestampMicroseconds, 500000u);
}

TEST(PcapNgTimestampResolution, NanosecondFileRoundtripsThroughWriter) {
    // Reading a nanosecond file and writing it with the (microsecond) PcapNG writer
    // must preserve the timestamp at microsecond precision.
    const TempFile input;
    const TempFile output;
    writePcapNg(input.path, 9, 1700000000ULL * 1'000'000'000 + 123456789);

    {
        // keep the reader alive while writing, packet.data points into its mapping
        fpcap::pcapng::MMPcapNgReader reader{input.path};
        fpcap::pcapng::StreamPcapNgWriter writer{output.path, false};
        fpcap::Packet packet;
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                writer.write(packet);
            }
        }
    }

    const auto roundtripped = readSinglePacket(output.path);
    EXPECT_EQ(roundtripped.timestampSeconds, 1700000000u);
    EXPECT_EQ(roundtripped.timestampMicroseconds, 123456u);
}

TEST(PcapNgTimestampResolution, UnsupportedResolutionThrows) {
    // 10^-32 used to produce a resolution of 0 and a division by zero
    const TempFile file;
    writePcapNg(file.path, 32, 1);
    EXPECT_THROW(readSinglePacket(file.path), std::runtime_error);
}
