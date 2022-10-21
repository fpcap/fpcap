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
#include <sys/mman.h>
#include <unistd.h>
#elif _WIN32
#include <memoryapi.h>
#include <winsock2.h>
#include <windows.h>
#endif

namespace mmpr {

#if _WIN32
// Windows HANDLEs are not RAII compatible, therefore we need to wrap them
// See https://stackoverflow.com/a/34405788
class WinHandle {
public:
    WinHandle(std::nullptr_t = nullptr) : value_(nullptr) {}
    WinHandle(HANDLE value) : value_(value == INVALID_HANDLE_VALUE ? nullptr : value) {}

    explicit operator bool() const { return value_ != nullptr; }
    operator HANDLE() const { return value_; }

    friend bool operator==(WinHandle l, WinHandle r) { return l.value_ == r.value_; }
    friend bool operator!=(WinHandle l, WinHandle r) { return !(l == r); }

    struct Deleter {
        typedef WinHandle pointer;
        void operator()(WinHandle handle) const { CloseHandle(handle); }
    };

private:
    HANDLE value_;
};

inline bool operator==(HANDLE l, WinHandle r) {
    return WinHandle(l) == r;
}
inline bool operator!=(HANDLE l, WinHandle r) {
    return !(l == r);
}
inline bool operator==(WinHandle l, HANDLE r) {
    return l == WinHandle(r);
}
inline bool operator!=(WinHandle l, HANDLE r) {
    return !(l == r);
}

typedef std::unique_ptr<WinHandle, WinHandle::Deleter> HandlePtr;
#endif

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
        mFileHandle = HandlePtr(CreateFile(mFilepath.c_str(), GENERIC_READ,
                                           /*shared mode*/ 0,
                                           /*security*/ nullptr, OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL,
                                           /*template*/ nullptr));
        if (!mFileHandle) {
            throw std::runtime_error("could not create file handle for " + mFilepath);
        }

        mFileMappingHandle = HandlePtr(CreateFileMapping(mFileHandle.get(), NULL,
                                                         PAGE_READONLY, /*size high*/ 0,
                                                         /*size low*/ 0, NULL));
        if (!mFileMappingHandle) {
            throw std::runtime_error("could not create file mapping handle for " +
                                     mFilepath);
        }

        // map the input file
        auto mmapResult = MapViewOfFile(mFileMappingHandle.get(), FILE_MAP_READ, 0, 0, 0);
        if (mmapResult == nullptr) {
            throw std::runtime_error("failed to map file to memory: " + mFilepath);
        }

        mOffset = 0;
        mMappedMemory = reinterpret_cast<const uint8_t*>(mmapResult);
#endif
    }

    MMapFileReader(mmpr::ZstdFileReader reader);

#if __linux__
    ~MMapFileReader() {
        munmap((void*)mMappedMemory, mFileSize);
        ::close(mFileDescriptor);
    }
#endif

    const uint8_t* data() const override { return mMappedMemory; }

private:
#if __linux__
    int mFileDescriptor{0};
#elif _WIN32
    HandlePtr mFileHandle;
    HandlePtr mFileMappingHandle;
#endif
    const uint8_t* mMappedMemory{nullptr};
};

} // namespace mmpr

#endif // MMPR_MMAPFILEREADER_HPP
