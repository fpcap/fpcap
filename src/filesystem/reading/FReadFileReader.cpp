#include "mmpr/filesystem/reading/FReadFileReader.hpp"

namespace mmpr {

FReadFileReader::FReadFileReader(const std::string& filepath) : FileReader(filepath) {
    mFileContent = std::unique_ptr<uint8_t>(new uint8_t[mFileSize]);
    FILE* const inFile = fopen(mFilepath.c_str(), "rb");
    if (fread(mFileContent.get(), 1, mFileSize, inFile) != mFileSize) {
        throw std::runtime_error("fread error: " + std::string(strerror(errno)));
    }
    fclose(inFile);
    mFileContentPtr = mFileContent.get();
}

} // namespace mmpr
