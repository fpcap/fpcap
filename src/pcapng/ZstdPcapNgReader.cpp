#ifdef MMPR_USE_ZSTD

#include "mmpr/pcapng/ZstdPcapNgReader.h"

#include "mmpr/ZstdDecompressor.h"
#include "util.h"
#include <algorithm>
#include <sstream>

using namespace std;

namespace mmpr {

ZstdPcapNgReader::ZstdPcapNgReader(const std::string& filepath) : PcapNgReader(filepath) {
    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    if (magicNumber != MMPR_MAGIC_NUMBER_ZSTD) {
        stringstream sstream;
        sstream << std::hex << magicNumber;
        string hex = sstream.str();
        std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
        throw std::runtime_error("Expected ZSTD format to start with appropriate magic "
                                 "number, instead got: 0x" +
                                 hex + ", possibly little/big endian issue");
    }
}

void ZstdPcapNgReader::open() {
    mData = reinterpret_cast<const uint8_t*>(
        ZstdDecompressor::decompressFileInMemory(mFilepath, mFileSize));
    assert(mFileSize > 0);
}

} // namespace mmpr

#endif