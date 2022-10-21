#ifndef MMPR_MMAPFILEREADER_HPP
#define MMPR_MMAPFILEREADER_HPP

#if __linux__

#include "FileReader.hpp"
#include "ZstdFileReader.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

namespace mmpr {

class MMapFileReader : public FileReader {
public:
    MMapFileReader(const std::string& filepath) : FileReader(filepath) {
        mFileDescriptor = ::open(mFilepath.c_str(), O_RDONLY, 0);
        if (mFileDescriptor < 0) {
            throw std::runtime_error("Error while reading file " +
                                     std::filesystem::absolute(mFilepath).string() +
                                     ": " + strerror(errno));
        }

        auto mmapResult =
            mmap(nullptr, mFileSize, PROT_READ, MAP_SHARED, mFileDescriptor, 0);
        if (mmapResult == MAP_FAILED) {
            ::close(mFileDescriptor);
            throw std::runtime_error("Error while mapping file " +
                                     std::filesystem::absolute(mFilepath).string() +
                                     ": " + strerror(errno));
        }

        mOffset = 0;
        mMappedMemory = reinterpret_cast<const uint8_t*>(mmapResult);
    }

    MMapFileReader(mmpr::ZstdFileReader reader);
    ~MMapFileReader() {
        munmap((void*)mMappedMemory, mFileSize);
        ::close(mFileDescriptor);
    }

    const uint8_t* data() const override { return mMappedMemory; }

private:
    int mFileDescriptor{0};
    const uint8_t* mMappedMemory{nullptr};
};

} // namespace mmpr

#endif

#endif // MMPR_MMAPFILEREADER_HPP
