#include "fpcap/filesystem/Reader.hpp"

#include <fpcap/util.hpp>
#include <fpcap/MagicNumber.hpp>

#include <filesystem>
#include <fpcap/modified_pcap/ModifiedPcapReader.hpp>
#include <fpcap/pcap/PcapReader.hpp>
#include <fpcap/pcapng/PcapNgReader.hpp>


using namespace std;

namespace fpcap {
unique_ptr<Reader> Reader::getReader(const string& filepath) {
    if (filepath.empty()) {
        throw runtime_error("cannot create reader for empty filepath");
    }

    if (!filesystem::exists(filepath)) {
        throw runtime_error("FileReader: could not find file \"" + filepath + "\"");
    }

    switch (util::read32bitsFromFile(filepath)) {
    case PCAP_MICROSECONDS:
    case PCAP_NANOSECONDS: {
        return make_unique<pcap::MMPcapReader>(filepath);
    }
    case PCAPNG: {
        return make_unique<pcapng::MMPcapNgReader>(filepath);
    }
    case MODIFIED_PCAP: {
        return make_unique<modified_pcap::MMModifiedPcapReader>(filepath);
    }
    case ZSTD: {
        ZstdFileReader compressedFileReader(filepath);
        switch (*reinterpret_cast<const uint32_t*>(compressedFileReader.data())) {
        case PCAP_MICROSECONDS:
        case PCAP_NANOSECONDS: {
            return make_unique<pcap::ZstdPcapReader>(std::move(compressedFileReader));
        }
        case PCAPNG: {
            return make_unique<pcapng::ZstdPcapNgReader>(std::move(compressedFileReader));
        }
        case MODIFIED_PCAP: {
            return make_unique<modified_pcap::ZstdModifiedPcapReader>(std::move(compressedFileReader));
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
}
