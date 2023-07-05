#include "fpcap/fpcap.hpp"

#include "fpcap/filesystem/writing/StreamFileWriter.hpp"
#include "fpcap/modified_pcap/ModifiedPcapReader.hpp"
#include "fpcap/pcap/PcapReader.hpp"
#include "fpcap/pcap/PcapWriter.hpp"
#include "fpcap/pcapng/PcapNgReader.hpp"
#include "fpcap/util.hpp"
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

using namespace std;

namespace fpcap {

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
        return make_unique<MMPcapReader>(filepath);
    }
    case PCAPNG: {
        return make_unique<MMPcapNgReader>(filepath);
    }
    case MODIFIED_PCAP: {
        return make_unique<MMModifiedPcapReader>(filepath);
    }
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

} // namespace fpcap
