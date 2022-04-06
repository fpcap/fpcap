#include <mmpr/mmpr.h>

#include <boost/algorithm/string/predicate.hpp>
#include <mmpr/pcap/MMPcapReader.h>
#include <mmpr/pcapng/MMPcapNgReader.h>
#include <mmpr/pcapng/ZstdPcapNgReader.h>

namespace mmpr {

FileReader::FileReader(const std::string& filepath) : mFilepath(filepath) {}

FileReader* FileReader::getReader(const std::string& filepath) {
    if (boost::algorithm::ends_with(filepath, ".pcap")) {
        return new MMPcapReader(filepath);
    } else if (boost::algorithm::ends_with(filepath, ".pcap.zst") ||
               boost::algorithm::ends_with(filepath, ".pcap.zstd")) {
        // TODO implement
        // return ZstdPcapReader();
        throw std::runtime_error("not yet implemented");
    } else if (boost::algorithm::ends_with(filepath, ".pcapng")) {
        return new MMPcapNgReader(filepath);
    } else if (boost::algorithm::ends_with(filepath, ".pcapng.zst") ||
               boost::algorithm::ends_with(filepath, ".pcapng.zstd")) {
        return new ZstdPcapNgReader(filepath);
    } else {
        throw std::runtime_error(
            "Currently only supporting the following file endings: .pcap, "
            ".pcapng, .zst and .zstd");
    }
}

} // namespace mmpr