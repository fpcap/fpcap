#include <mmpr/pcapng/ZstdPcapNgReader.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <mmpr/ZstdDecompressor.h>

using namespace std;
using namespace boost::filesystem;
using namespace boost::algorithm;

namespace mmpr {

ZstdPcapNgReader::ZstdPcapNgReader(const std::string& filepath) : PcapNgReader(filepath) {
    // TODO determine by file header or similar
    if (!ends_with(filepath, ".zst") && !ends_with(filepath, ".zstd")) {
        throw runtime_error(
            "ZstdPcapNgReader only supports files with .zst or .zstd endings");
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
