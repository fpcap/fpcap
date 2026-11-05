#ifndef FPCAP_TEST_TESTFILES_HPP
#define FPCAP_TEST_TESTFILES_HPP

#include <gtest/gtest.h>

#include <fpcap/util.hpp>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace fpcap::test {

// File in the temp directory, named after the running test and removed on destruction
class TempFile {
public:
    explicit TempFile(const std::vector<uint8_t>& bytes) {
        const auto* test = testing::UnitTest::GetInstance()->current_test_info();
        // Parameterized test names contain '/'
        std::string name = std::string(test->test_suite_name()) + "_" + test->name();
        std::replace(name.begin(), name.end(), '/', '_');
        mPath = (std::filesystem::temp_directory_path() /
                 ("fpcap_test_" + name + "_" + std::to_string(std::random_device{}())))
                    .string();
        std::ofstream out(mPath, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        if (!out.flush()) {
            throw std::runtime_error("cannot write " + mPath);
        }
    }

    ~TempFile() {
        std::error_code error;
        std::filesystem::remove(mPath, error);
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    const std::string& path() const { return mPath; }

private:
    std::string mPath;
};

inline void swap16(std::vector<uint8_t>& bytes, const size_t offset) {
    uint16_t value;
    std::memcpy(&value, &bytes[offset], sizeof(value));
    value = util::byteSwap16(value);
    std::memcpy(&bytes[offset], &value, sizeof(value));
}

inline void swap32(std::vector<uint8_t>& bytes, const size_t offset) {
    uint32_t value;
    std::memcpy(&value, &bytes[offset], sizeof(value));
    value = util::byteSwap32(value);
    std::memcpy(&bytes[offset], &value, sizeof(value));
}

/**
 * Returns the contents of a pcap (recordHeaderLength 16) or modified pcap
 * (recordHeaderLength 24) with every multi-byte field in the opposite byte order.
 */
inline std::vector<uint8_t> byteSwappedCopy(const std::string& filepath,
                                            const size_t recordHeaderLength) {
    std::ifstream in(filepath, std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in), {}};
    if (bytes.size() < 24) {
        throw std::runtime_error("cannot read " + filepath);
    }

    // The trace files are little-endian, but detect it to work on any host
    const bool littleEndianFile = bytes[3] == 0xA1;
    swap32(bytes, 0);
    swap16(bytes, 4);
    swap16(bytes, 6);
    for (size_t offset = 8; offset < 24; offset += 4) {
        swap32(bytes, offset);
    }
    for (size_t offset = 24; offset + recordHeaderLength <= bytes.size();) {
        const auto* length = &bytes[offset + 8];
        const uint32_t captureLength =
            littleEndianFile ? (length[0] | length[1] << 8 | length[2] << 16 |
                                static_cast<uint32_t>(length[3]) << 24)
                             : (static_cast<uint32_t>(length[0]) << 24 |
                                length[1] << 16 | length[2] << 8 | length[3]);
        for (size_t field = 0; field < 16; field += 4) {
            swap32(bytes, offset + field);
        }
        if (recordHeaderLength == 24) {
            swap32(bytes, offset + 16); // interface index
            swap16(bytes, offset + 20); // protocol
        }
        offset += recordHeaderLength + captureLength;
    }
    return bytes;
}

// Writes value at offset in the byte order opposite to the host's
inline void putSwapped16(uint8_t* data, const size_t offset, const uint16_t value) {
    const uint16_t swapped = util::byteSwap16(value);
    std::memcpy(&data[offset], &swapped, sizeof(swapped));
}

inline void putSwapped32(uint8_t* data, const size_t offset, const uint32_t value) {
    const uint32_t swapped = util::byteSwap32(value);
    std::memcpy(&data[offset], &swapped, sizeof(swapped));
}

} // namespace fpcap::test

#endif // FPCAP_TEST_TESTFILES_HPP
