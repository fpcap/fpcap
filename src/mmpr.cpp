#include "mmpr/mmpr.h"

#include "mmpr/modified_pcap/ModifiedPcapReader.h"
#include "mmpr/pcap/PcapReader.h"
#include "mmpr/pcapng/PcapNgReader.h"
#include "mmpr/util.h"
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

using namespace std;

namespace mmpr {

unique_ptr<Reader> Reader::getReader(const string& filepath) {
    if (!filesystem::exists(filepath)) {
        throw runtime_error("FileReader: could not find file \"" + filepath + "\"");
    }

    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    switch (magicNumber) {
    case MMPR_MAGIC_NUMBER_PCAP_MICROSECONDS:
    case MMPR_MAGIC_NUMBER_PCAP_NANOSECONDS: {
        return make_unique<MMPcapReader>(filepath);
    }
    case MMPR_MAGIC_NUMBER_PCAPNG: {
        return make_unique<MMPcapNgReader>(filepath);
    }
    case MMPR_MAGIC_NUMBER_MODIFIED_PCAP: {
        return make_unique<MMModifiedPcapReader>(filepath);
    }
#ifdef MMPR_USE_ZSTD
    case MMPR_MAGIC_NUMBER_ZSTD: {
        ZstdFileReader compressedFileReader(filepath);
        auto uncompressedMagicNumber = *(uint32_t*)compressedFileReader.data();
        switch (uncompressedMagicNumber) {
        case MMPR_MAGIC_NUMBER_PCAP_MICROSECONDS:
        case MMPR_MAGIC_NUMBER_PCAP_NANOSECONDS: {
            return make_unique<ZstdPcapReader>(std::move(compressedFileReader));
        }
        case MMPR_MAGIC_NUMBER_PCAPNG: {
            return make_unique<ZstdPcapNgReader>(std::move(compressedFileReader));
        }
        case MMPR_MAGIC_NUMBER_MODIFIED_PCAP: {
            return make_unique<ZstdModifiedPcapReader>(std::move(compressedFileReader));
        }
        default:
            throw runtime_error("Failed to determine file type after decompression based "
                                "on first 32 bits");
        }
    }
#endif
    default:
        throw runtime_error("Failed to determine file type based on first 32 bits");
    }
}

} // namespace mmpr