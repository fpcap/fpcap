#include "mmpr/filesystem/reading/FReadFileReader.hpp"

#ifdef _WIN32
#include <stdio.h>
#endif

namespace mmpr {


FReadFileReader::FReadFileReader(const std::string& filepath) : FileReader(filepath) {
    mFileContent = std::make_unique<uint8_t[]>(mFileSize);

#ifdef __linux__
    FILE* const inFile = fopen(mFilepath.c_str(), "rb");
    if (fread(mFileContent.get(), 1, mFileSize, inFile) != mFileSize) {
        throw std::runtime_error("fread error: " + std::string(strerror(errno)));
    }
#else
    FILE* inFile;
    errno_t err = fopen_s(&inFile, mFilepath.c_str(), "rb");
    if (err != 0) {
        throw std::runtime_error("fopen_s error: " + std::to_string(err));
    }

    if (fread(mFileContent.get(), 1, mFileSize, inFile) != mFileSize) {
        throw std::runtime_error("fread error: " + std::to_string(errno));
    }
#endif
    fclose(inFile);
    mFileContentPtr = mFileContent.get();
}

} // namespace mmpr
