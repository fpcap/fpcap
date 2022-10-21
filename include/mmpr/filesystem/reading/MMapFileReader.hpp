#ifndef MMPR_MMAPFILEREADER_HPP
#define MMPR_MMAPFILEREADER_HPP

#include "FileReader.hpp"
#include "ZstdFileReader.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#if __linux__
#include <unistd.h>
#include <sys/mman.h>
#elif _WIN32
#include <winsock2.h>
#include <memoryapi.h>
#include <windows.h>
#endif

namespace mmpr {

class MMapFileReader : public FileReader {
public:
    MMapFileReader(const std::string& filepath) : FileReader(filepath) {

#if __linux__
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
#elif _WIN32
        mFileHandle = CreateFile(mFilepath.c_str(), GENERIC_READ,
                              /*shared mode*/ 0,
                              /*security*/ nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              /*template*/ nullptr);
        mFileMappingHandle = CreateFileMapping(mFileHandle, NULL, PAGE_READONLY, /*size high*/ 0,
                                           /*size low*/ 0, NULL);

        if (!mFileMappingHandle) {
            CloseHandle(mFileHandle);
            throw std::runtime_error("!hInputMap");
        }

        /* Map the input file */
        auto mmapResult = MapViewOfFile(mFileMappingHandle, FILE_MAP_READ, 0, 0, 0);
        if (mmapResult == nullptr) {
            CloseHandle(mFileMappingHandle);
            CloseHandle(mFileHandle);
            throw std::runtime_error("ptrInFile == nullptr");
        }

        mOffset = 0;
        mMappedMemory = reinterpret_cast<const uint8_t*>(mmapResult);
#endif
    }

#if MMPR_USE_ZSTD
    MMapFileReader(mmpr::ZstdFileReader reader);
#endif

    ~MMapFileReader() {
#if __linux__
        munmap((void*)mMappedMemory, mFileSize);
        ::close(mFileDescriptor);
#elif _WIN32
        CloseHandle(mFileMappingHandle);
        CloseHandle(mFileHandle);
#endif
    }

    const uint8_t* data() const override { return mMappedMemory; }

private:
#if __linux__
    int mFileDescriptor{0};
#elif _WIN32
    HANDLE mFileHandle;
    HANDLE mFileMappingHandle;
#endif
    const uint8_t* mMappedMemory{nullptr};
};

} // namespace mmpr

#endif // MMPR_MMAPFILEREADER_HPP
