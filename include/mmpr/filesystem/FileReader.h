#ifndef MMPR_FILEREADER_H
#define MMPR_FILEREADER_H

#include "mmpr/mmpr.h"
#include <filesystem>
#include <string>

namespace mmpr {

class FileReader {
public:
    FileReader(const std::string& filePath)
        : mFilePath(filePath), mFileSize(std::filesystem::file_size(filePath)) {}

    virtual const uint8_t* data() const = 0;

    std::size_t getSafeToReadSize() const {
        if (mOffset >= mFileSize) {
            return 0;
        } else {
            return mFileSize - mOffset;
        }
    }

    bool isExhausted() const { return mOffset >= mFileSize; }

    const std::string mFilePath;
    const std::size_t mFileSize;
    std::size_t mOffset{0};
};

} // namespace mmpr

#endif // MMPR_FILEREADER_H
