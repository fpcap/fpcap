#ifndef MMPR_FILEREADER_HPP
#define MMPR_FILEREADER_HPP

#include "mmpr/mmpr.hpp"
#include <filesystem>
#include <string>

namespace mmpr {

class FileReader {
public:
    FileReader(const std::string& filepath);

    virtual const uint8_t* data() const = 0;

    std::size_t getSafeToReadSize() const;

    bool isExhausted() const { return mOffset >= mFileSize; }

    const std::string mFilepath;
    std::size_t mFileSize;
    std::size_t mOffset{0};
};

} // namespace mmpr

#endif // MMPR_FILEREADER_HPP
