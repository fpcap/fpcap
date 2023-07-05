#include "fpcap/filesystem/reading/FReadFileReader.hpp"

#if defined(_WIN32) || defined(__APPLE__)
#include <stdio.h>
#endif

namespace fpcap {

FReadFileReader::FReadFileReader(const std::string& filepath) : FileReader(filepath) {
    mFileContent = std::make_unique<uint8_t[]>(mFileSize);

#ifdef _WIN32
    FILE* inFile;
    errno_t err = fopen_s(&inFile, mFilepath.c_str(), "rb");
    if (err != 0) {
        throw std::runtime_error("fopen_s error: " + std::to_string(err));
    }

    if (fread(mFileContent.get(), 1, mFileSize, inFile) != mFileSize) {
        throw std::runtime_error("fread error: " + std::to_string(errno));
    }

#else
    FILE* const inFile = fopen(mFilepath.c_str(), "rb");
    if (fread(mFileContent.get(), 1, mFileSize, inFile) != mFileSize) {
        throw std::runtime_error("fread error: " + std::string(strerror(errno)));
    }
#endif
    fclose(inFile);
    mFileContentPtr = mFileContent.get();
}

} // namespace fpcap
