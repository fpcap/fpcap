#ifndef MMPR_FILEREADER_HPP
#define MMPR_FILEREADER_HPP

#include "mmpr/mmpr.hpp"
#include <filesystem>
#include <string>

namespace mmpr {

class FileReader {
public:
    FileReader(const std::string& filepath)
        : mFilepath(filepath), mFileSize(std::filesystem::file_size(filepath)) {
        if (filepath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!std::filesystem::exists(filepath)) {
            throw std::runtime_error("Cannot find file " +
                                     std::filesystem::absolute(filepath).string());
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

    const std::string mFilepath;
    std::size_t mFileSize;
    std::size_t mOffset{0};
};

} // namespace mmpr

#endif // MMPR_FILEREADER_HPP
