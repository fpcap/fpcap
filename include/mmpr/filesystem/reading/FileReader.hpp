#ifndef MMPR_FILEREADER_HPP
#define MMPR_FILEREADER_HPP

#include "mmpr/mmpr.hpp"
#include <filesystem>
#include <string>

namespace mmpr {

class FileReader {
public:
    FileReader(const std::string& filePath)
        : mFilePath(filePath), mFileSize(std::filesystem::file_size(filePath)) {
        if (filePath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!std::filesystem::exists(filePath)) {
            throw std::runtime_error("Cannot find file " +
                                     std::filesystem::absolute(filePath).string());
        }
    }

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
    std::size_t mFileSize;
    std::size_t mOffset{0};
};

} // namespace mmpr

#endif // MMPR_FILEREADER_HPP
