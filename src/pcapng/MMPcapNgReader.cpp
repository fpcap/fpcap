#include <mmpr/pcapng/MMPcapNgReader.h>

#include "util.h"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <mmpr/pcapng/PcapNgBlockParser.h>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

using namespace std;
using namespace boost::filesystem;
using namespace boost::algorithm;

namespace mmpr {

MMPcapNgReader::MMPcapNgReader(const string& filepath) : PcapNgReader(filepath) {
    // TODO determine by file header or similar
    if (!ends_with(filepath, ".pcapng")) {
        throw runtime_error("MMPcapNgReader only supports files with .pcapng endings");
    }
}

void MMPcapNgReader::open() {
    mFileDescriptor = ::open(mFilepath.c_str(), O_RDONLY, 0);
    if (mFileDescriptor < 0) {
        throw runtime_error("Error while reading file " + canonical(mFilepath).string() +
                            ": " + strerror(errno));
    }

    mFileSize = lseek(mFileDescriptor, 0, SEEK_END);
    mMappedSize = (mFileSize / MMPR_PAGE_SIZE + 1) * MMPR_PAGE_SIZE;

    auto mmapResult =
        mmap(nullptr, mMappedSize, PROT_READ, MAP_SHARED, mFileDescriptor, 0);
    if (mmapResult == MAP_FAILED) {
        ::close(mFileDescriptor);
        throw runtime_error("Error while mapping file " + canonical(mFilepath).string() +
                            ": " + strerror(errno));
    }

    mOffset = 0;
    mData = reinterpret_cast<const uint8_t*>(mmapResult);
}

void MMPcapNgReader::close() {
    munmap((void*)mData, mMappedSize);
    ::close(mFileDescriptor);
}

} // namespace mmpr
