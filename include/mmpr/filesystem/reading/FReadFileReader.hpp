#ifndef MMPR_FREADFILEREADER_HPP
#define MMPR_FREADFILEREADER_HPP

#include "FileReader.hpp"
#include <cstring>
#include <filesystem>
#include <memory>
#include <stdexcept>

namespace mmpr {

class FReadFileReader : public FileReader {
public:
    FReadFileReader(const std::string& filePath) : FileReader(filePath) {
        mFileContent = std::unique_ptr<uint8_t>(new uint8_t[mFileSize]);
        FILE* const inFile = fopen(mFilePath.c_str(), "rb");
        if (fread(mFileContent.get(), 1, mFileSize, inFile) != mFileSize) {
            throw std::runtime_error("fread error: " + std::string(strerror(errno)));
        }
        fclose(inFile);
        mFileContentPtr = mFileContent.get();
    }

    const uint8_t* data() const override { return mFileContentPtr; }

private:
    std::unique_ptr<uint8_t> mFileContent;
    const uint8_t* mFileContentPtr;
};

} // namespace mmpr

#endif // MMPR_FREADFILEREADER_HPP
