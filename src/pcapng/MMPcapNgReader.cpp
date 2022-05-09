#include <mmpr/pcapng/MMPcapNgReader.h>

#include "util.h"
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/filesystem.hpp>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <mmpr/pcapng/PcapNgBlockParser.h>
#include <sstream>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

using namespace std;
using namespace boost::filesystem;
using namespace boost::algorithm;

namespace mmpr {

MMPcapNgReader::MMPcapNgReader(const string& filepath) : PcapNgReader(filepath) {
    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    if (magicNumber != MMPR_MAGIC_NUMBER_PCAPNG) {
        stringstream sstream;
        sstream << std::hex << magicNumber;
        string hex = sstream.str();
        boost::to_upper(hex);
        throw std::runtime_error("Expected PcapNG format to start with appropriate magic "
                                 "number, instead got: 0x" +
                                 hex);
    }
}

void MMPcapNgReader::open() {
    mFileDescriptor = ::open(mFilepath.c_str(), O_RDONLY, 0);
    if (mFileDescriptor < 0) {
        throw runtime_error("Error while reading file " + absolute(mFilepath).string() +
                            ": " + strerror(errno));
    }

    mFileSize = lseek(mFileDescriptor, 0, SEEK_END);
    mMappedSize = (mFileSize / MMPR_PAGE_SIZE + 1) * MMPR_PAGE_SIZE;

    auto mmapResult =
        mmap(nullptr, mMappedSize, PROT_READ, MAP_SHARED, mFileDescriptor, 0);
    if (mmapResult == MAP_FAILED) {
        ::close(mFileDescriptor);
        throw runtime_error("Error while mapping file " + absolute(mFilepath).string() +
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
