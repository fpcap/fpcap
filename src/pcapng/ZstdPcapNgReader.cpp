#include <mmpr/pcapng/ZstdPcapNgReader.h>

#include "util.h"
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/filesystem.hpp>
#include <mmpr/ZstdDecompressor.h>
#include <sstream>

using namespace std;
using namespace boost::filesystem;
using namespace boost::algorithm;

namespace mmpr {

ZstdPcapNgReader::ZstdPcapNgReader(const std::string& filepath) : PcapNgReader(filepath) {
    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    if (magicNumber != MMPR_MAGIC_NUMBER_ZSTD) {
        stringstream sstream;
        sstream << std::hex << magicNumber;
        string hex = sstream.str();
        boost::to_upper(hex);
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

void ZstdPcapNgReader::close() {
    free((void*)mData);
}

} // namespace mmpr
