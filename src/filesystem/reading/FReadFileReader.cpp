#include "mmpr/filesystem/reading/FReadFileReader.hpp"

#ifdef _WIN32
#include <stdio.h>
#endif

namespace mmpr {

#ifdef __linux__
FReadFileReader::FReadFileReader(const std::string& filepath) : FileReader(filepath) {
    mFileContent = std::unique_ptr<uint8_t>(new uint8_t[mFileSize]);
    FILE* const inFile = fopen(mFilepath.c_str(), "rb");
    if (fread(mFileContent.get(), 1, mFileSize, inFile) != mFileSize) {
        throw std::runtime_error("fread error: " + std::string(strerror(errno)));
    }
    fclose(inFile);
    mFileContentPtr = mFileContent.get();
}
#else
FReadFileReader::FReadFileReader(const std::string& filepath) : FileReader(filepath) {
    mFileContent = std::unique_ptr<uint8_t>(new uint8_t[mFileSize]);

    FILE* inFile;
    errno_t err = fopen_s(&inFile, mFilepath.c_str(), "rb");
    if (err != 0) {
        throw std::runtime_error("fopen_s error: " + std::to_string(err));
    }

    if (fread(mFileContent.get(), 1, mFileSize, inFile) != mFileSize) {
        throw std::runtime_error("fread error: " + std::to_string(errno));
    }
    fclose(inFile);
    mFileContentPtr = mFileContent.get();
}
#endif

} // namespace mmpr
