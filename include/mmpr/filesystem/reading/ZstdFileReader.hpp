#ifndef MMPR_ZSTDFILEREADER_HPP
#define MMPR_ZSTDFILEREADER_HPP

#include "mmpr/filesystem/reading/FileReader.hpp"
#include <cstdint>
#include <memory>
#include <string>

namespace mmpr {

class ZstdFileReader : public FileReader {
public:
    ZstdFileReader(const std::string& filepath);

    ZstdFileReader(ZstdFileReader&& other)
        : FileReader(other.mFilepath),
          mDecompressedData(std::move(other.mDecompressedData)),
          mDecompressedDataPtr(mDecompressedData.get()) {}

    const uint8_t* data() const override { return mDecompressedDataPtr; }

private:
    std::unique_ptr<uint8_t> mDecompressedData;
    const uint8_t* mDecompressedDataPtr;
};

} // namespace mmpr

#endif // MMPR_ZSTDFILEREADER_HPP
