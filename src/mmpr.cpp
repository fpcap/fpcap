#include "mmpr/mmpr.hpp"

#include "mmpr/filesystem/writing/StreamFileWriter.hpp"
#include "mmpr/modified_pcap/ModifiedPcapReader.hpp"
#include "mmpr/pcap/PcapReader.hpp"
#include "mmpr/pcap/PcapWriter.hpp"
#include "mmpr/pcapng/PcapNgReader.hpp"
#include "mmpr/util.hpp"
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

using namespace std;

namespace mmpr {

unique_ptr<Reader> Reader::getReader(const string& filepath) {
    if (filepath.empty()) {
        throw runtime_error("cannot create reader for empty filepath");
    }
    if (!filesystem::exists(filepath)) {
        throw runtime_error("FileReader: could not find file \"" + filepath + "\"");
    }

    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    switch (magicNumber) {
    case PCAP_MICROSECONDS:
    case PCAP_NANOSECONDS: {
#if __linux__
        return make_unique<MMPcapReader>(filepath);
#else
        return make_unique<FReadPcapReader>(filepath);
#endif
    }
    case PCAPNG: {
#if __linux__
        return make_unique<MMPcapNgReader>(filepath);
#else
        return make_unique<FReadPcapNgReader>(filepath);
#endif
    }
    case MODIFIED_PCAP: {
#if __linux__
        return make_unique<MMModifiedPcapReader>(filepath);
#else
        return make_unique<FReadModifiedPcapReader>(filepath);
#endif
    }
#ifdef MMPR_USE_ZSTD
    case ZSTD: {
        ZstdFileReader compressedFileReader(filepath);
        auto uncompressedMagicNumber = *(uint32_t*)compressedFileReader.data();
        switch (uncompressedMagicNumber) {
        case PCAP_MICROSECONDS:
        case PCAP_NANOSECONDS: {
            return make_unique<ZstdPcapReader>(std::move(compressedFileReader));
        }
        case PCAPNG: {
            return make_unique<ZstdPcapNgReader>(std::move(compressedFileReader));
        }
        case MODIFIED_PCAP: {
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

unique_ptr<Writer> Writer::getWriter(const string& filepath) {
    if (filepath.empty()) {
        throw runtime_error("cannot writer reader for empty filepath");
    }

    return make_unique<StreamPcapWriter>(filepath);
}

} // namespace mmpr