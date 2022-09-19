#include "mmpr/mmpr.h"

#include "mmpr/pcap/MMPcapReader.h"
#include "mmpr/pcapng/MMPcapNgReader.h"
#ifdef MMPR_USE_ZSTD
#include "mmpr/pcapng/ZstdPcapNgReader.h"
#endif
#ifdef MMPR_USE_GZIP
#include "mmpr/pcap/GzipPcapReader.h"
#endif
#include "mmpr/modified_pcap/MMModifiedPcapReader.h"
#include "util.h"
#include <filesystem>
#include <iostream>
#include <memory>

namespace mmpr {

FileReader::FileReader(const std::string& filepath) : mFilepath(filepath) {}

std::unique_ptr<FileReader> FileReader::getReader(const std::string& filepath) {
    if (!std::filesystem::exists(filepath)) {
        throw std::runtime_error("FileReader: could not find file \"" + filepath + "\"");
    }

    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    if (magicNumber == MMPR_MAGIC_NUMBER_PCAP_MICROSECONDS || magicNumber == MMPR_MAGIC_NUMBER_PCAP_NANOSECONDS) {
        return std::unique_ptr<MMPcapReader>(new MMPcapReader(filepath));
    }
    else if(magicNumber == MMPR_MAGIC_NUMBER_PCAPNG) {
        return std::unique_ptr<MMPcapNgReader>(new MMPcapNgReader(filepath));
    }
#ifdef MMPR_USE_ZSTD
    else if (magicNumber == MMPR_MAGIC_NUMBER_ZSTD) {
        return std::unique_ptr<ZstdPcapNgReader>(new ZstdPcapNgReader(filepath));
    }
#endif
#ifdef MMPR_USE_GZIP
    else if (magicNumber >> 16 == MMPR_MAGIC_NUMBER_GZIP) {
        // TODO switch between PCAP and PCAPNG
        return std::unique_ptr<GzipPcapReader>(new GzipPcapReader(filepath));
    }
#endif
    else if (magicNumber == MMPR_MAGIC_NUMBER_MODIFIED_PCAP) {
        return std::unique_ptr<MMModifiedPcapReader>(new MMModifiedPcapReader(filepath));
    }

    throw std::runtime_error("Failed to determine file type based on first 32 bits");
}

} // namespace mmpr