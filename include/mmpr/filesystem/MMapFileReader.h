#ifndef MMPR_MMAPFILEREADER_H
#define MMPR_MMAPFILEREADER_H

#include "FileReader.h"
#include "ZstdFileReader.h"
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
    MMapFileReader(const std::string& filePath) : FileReader(filePath) {
        mFileDescriptor = ::open(mFilePath.c_str(), O_RDONLY, 0);
        if (mFileDescriptor < 0) {
            throw std::runtime_error("Error while reading file " +
                                     std::filesystem::absolute(mFilePath).string() +
                                     ": " + strerror(errno));
        }

        long pageSize = sysconf(_SC_PAGESIZE);
        mMappedSize = (mFileSize / pageSize + 1) * pageSize;

        auto mmapResult =
            mmap(nullptr, mMappedSize, PROT_READ, MAP_SHARED, mFileDescriptor, 0);
        if (mmapResult == MAP_FAILED) {
            ::close(mFileDescriptor);
            throw std::runtime_error("Error while mapping file " +
                                     std::filesystem::absolute(mFilePath).string() +
                                     ": " + strerror(errno));
        }

        mOffset = 0;
        mMappedMemory = reinterpret_cast<const uint8_t*>(mmapResult);
    }

    MMapFileReader(mmpr::ZstdFileReader reader);
    ~MMapFileReader() {
        munmap((void*)mMappedMemory, mMappedSize);
        ::close(mFileDescriptor);
    }

    const uint8_t* data() const override { return mMappedMemory; }

private:
    int mFileDescriptor{0};
    size_t mMappedSize{0};
    const uint8_t* mMappedMemory{nullptr};
};

} // namespace mmpr

#endif // MMPR_MMAPFILEREADER_H