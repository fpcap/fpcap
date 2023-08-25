#include "fpcap/filesystem/reading/MMapFileReader.hpp"

namespace fpcap {

MMapFileReader::MMapFileReader(const std::string& filepath) : FileReader(filepath) {
#if __linux__ || __APPLE__
    mFileDescriptor = ::open(mFilepath.c_str(), O_RDONLY, 0);
    if (mFileDescriptor < 0) {
        throw std::runtime_error("Error while reading file " +
                                 std::filesystem::absolute(mFilepath).string() + ": " +
                                 strerror(errno));
    }

    auto mmapResult = mmap(nullptr, mFileSize, PROT_READ, MAP_SHARED, mFileDescriptor, 0);
    if (mmapResult == MAP_FAILED) {
        ::close(mFileDescriptor);
        throw std::runtime_error("Error while mapping file " +
                                 std::filesystem::absolute(mFilepath).string() + ": " +
                                 strerror(errno));
    }

    mOffset = 0;
    mMappedMemory = reinterpret_cast<const uint8_t*>(mmapResult);
#elif _WIN32
    mFileHandle =
        HandlePtr(CreateFile(mFilepath.c_str(), GENERIC_READ,
                             /*shared mode*/ 0,
                             /*security*/ nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                             /*template*/ nullptr));
    if (!mFileHandle) {
        throw std::runtime_error("could not create file handle for " + mFilepath);
    }

    mFileMappingHandle = HandlePtr(CreateFileMapping(mFileHandle.get(), NULL,
                                                     PAGE_READONLY, /*size high*/ 0,
                                                     /*size low*/ 0, NULL));
    if (!mFileMappingHandle) {
        throw std::runtime_error("could not create file mapping handle for " + mFilepath);
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

} // namespace fpcap
