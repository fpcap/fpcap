#include "mmpr/pcapng/MMPcapNgReader.h"

#include "mmpr/pcapng/PcapNgBlockParser.h"
#include "util.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

using namespace std;

namespace mmpr {

MMPcapNgReader::MMPcapNgReader(const string& filepath) : PcapNgReader(filepath) {
    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    if (magicNumber != MMPR_MAGIC_NUMBER_PCAPNG) {
        stringstream sstream;
        sstream << std::hex << magicNumber;
        string hex = sstream.str();
        std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
        throw std::runtime_error("Expected PcapNG format to start with appropriate magic "
                                 "number, instead got: 0x" +
                                 hex + ", possibly little/big endian issue");
    }
}

void MMPcapNgReader::open() {
    mFileDescriptor = ::open(mFilepath.c_str(), O_RDONLY, 0);
    if (mFileDescriptor < 0) {
        throw runtime_error("Error while reading file " +
                            std::filesystem::absolute(mFilepath).string() + ": " +
                            strerror(errno));
    }

    mFileSize = lseek(mFileDescriptor, 0, SEEK_END);
    long pageSize = sysconf (_SC_PAGESIZE);
    mMappedSize = (mFileSize / pageSize + 1) * pageSize;

    auto mmapResult =
        mmap(nullptr, mMappedSize, PROT_READ, MAP_SHARED, mFileDescriptor, 0);
    if (mmapResult == MAP_FAILED) {
        ::close(mFileDescriptor);
        throw runtime_error("Error while mapping file " +
                            std::filesystem::absolute(mFilepath).string() + ": " +
                            strerror(errno));
    }

    mOffset = 0;
    mData = reinterpret_cast<const uint8_t*>(mmapResult);
}

void MMPcapNgReader::close() {
    munmap((void*)mData, mMappedSize);
    ::close(mFileDescriptor);
}

} // namespace mmpr
