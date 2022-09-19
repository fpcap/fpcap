#include "mmpr/pcap/GzipPcapReader.h"

#include "../util.h"
#include "mmpr/GzipDecompressor.h"
#include "mmpr/pcap/PcapParser.h"
#include <algorithm>
#include <stdexcept>

using namespace std;

namespace mmpr {
GzipPcapReader::GzipPcapReader(const string& filepath) : PcapReader(filepath) {
    uint32_t magicNumber = util::read16bitsFromFile(filepath);
    if (magicNumber != MMPR_MAGIC_NUMBER_GZIP &&
        magicNumber != MMPR_MAGIC_NUMBER_GZIP_BE) {
        stringstream sstream;
        sstream << std::hex << magicNumber;
        string hex = sstream.str();
        std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
        throw std::runtime_error("Expected Gzip PCAP format to start with appropriate "
                                 "magic numbers, instead got: 0x" +
                                 hex + ", possibly little/big endian issue");
    }
}

void GzipPcapReader::open() {
    mData = reinterpret_cast<const uint8_t*>(
        GzipDecompressor::decompressFileInMemory(mFilepath, mFileSize));
}

bool GzipPcapReader::readNextPacket(Packet& packet) {
    return false;
}

} // namespace mmpr
