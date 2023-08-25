#ifndef FPCAP_MMAPFILEREADER_HPP
#define FPCAP_MMAPFILEREADER_HPP

#include "FileReader.hpp"
#include "ZstdFileReader.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#if __linux__ || __APPLE__
#include <sys/mman.h>
#include <unistd.h>
#elif _WIN32
#include <memoryapi.h>
#include <winsock2.h>
#include <windows.h>
#endif

namespace fpcap {

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
    MMapFileReader(const std::string& filepath);

    MMapFileReader(fpcap::ZstdFileReader reader);

#if __linux__ || __APPLE__
    ~MMapFileReader() {
        munmap((void*)mMappedMemory, mFileSize);
        ::close(mFileDescriptor);
    }
#endif

    const uint8_t* data() const override { return mMappedMemory; }

private:
#if __linux__ || __APPLE__
    int mFileDescriptor{0};
#elif _WIN32
    HandlePtr mFileHandle;
    HandlePtr mFileMappingHandle;
#endif
    const uint8_t* mMappedMemory{nullptr};
};

} // namespace fpcap

#endif // FPCAP_MMAPFILEREADER_HPP
