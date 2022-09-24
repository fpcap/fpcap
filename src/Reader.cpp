#include "mmpr/mmpr.h"

#include "mmpr/modified_pcap/MMModifiedPcapReader.h"
#include "mmpr/pcap/MMPcapReader.h"
#include "mmpr/pcapng/PcapNgReader.h"
#include "mmpr/util.h"
#include <filesystem>
#include <iostream>
#include <memory>

namespace mmpr {

std::unique_ptr<Reader> Reader::getReader(const std::string& filepath) {
    if (!std::filesystem::exists(filepath)) {
        throw std::runtime_error("FileReader: could not find file \"" + filepath + "\"");
    }

    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    switch (magicNumber) {
    case MMPR_MAGIC_NUMBER_PCAP_MICROSECONDS:
    case MMPR_MAGIC_NUMBER_PCAP_NANOSECONDS:
        return std::make_unique<MMPcapReader>(filepath);
    case MMPR_MAGIC_NUMBER_PCAPNG:
        return std::make_unique<MMPcapNgReader>(filepath);
#ifdef MMPR_USE_ZSTD
    case MMPR_MAGIC_NUMBER_ZSTD:
        return std::make_unique<ZstdPcapNgReader>(filepath);
#endif
    case MMPR_MAGIC_NUMBER_MODIFIED_PCAP:
        return std::make_unique<MMModifiedPcapReader>(filepath);
    default:
        throw std::runtime_error("Failed to determine file type based on first 32 bits");
    }
}

} // namespace mmpr