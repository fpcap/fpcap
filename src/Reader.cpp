#include <mmpr/mmpr.h>

#include "util.h"
#include <iostream>
#include <mmpr/pcap/MMPcapReader.h>
#include <mmpr/pcapng/MMPcapNgReader.h>
#include <mmpr/pcapng/ZstdPcapNgReader.h>

namespace mmpr {

FileReader::FileReader(const std::string& filepath) : mFilepath(filepath) {}

FileReader* FileReader::getReader(const std::string& filepath) {
    if (!boost::filesystem::exists(filepath)) {
        throw std::runtime_error("FileReader: could not find file \"" + filepath + "\"");
    }

    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    switch (magicNumber) {
    case MMPR_MAGIC_NUMBER_PCAP_MICROSECONDS:
    case MMPR_MAGIC_NUMBER_PCAP_NANOSECONDS:
        return new MMPcapReader(filepath);
    case MMPR_MAGIC_NUMBER_PCAPNG:
        return new MMPcapNgReader(filepath);
    case MMPR_MAGIC_NUMBER_ZSTD:
        return new ZstdPcapNgReader(filepath);
    default:
        throw std::runtime_error("Failed to determine file type based on first 32 bits");
    }
}

} // namespace mmpr