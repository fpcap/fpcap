#ifndef MMPR_ZSTDFILEREADER_HPP
#define MMPR_ZSTDFILEREADER_HPP

#if MMPR_USE_ZSTD

#include "FReadFileReader.hpp"
#include <algorithm>
#include <fstream>
#include <zstd.h>

namespace mmpr {

class ZstdFileReader : public FileReader {
public:
    ZstdFileReader(const std::string& filepath) : FileReader(filepath) {
        FReadFileReader compressedFileReader(mFilepath);
        auto compressedData = compressedFileReader.data();
        auto compressedSize = compressedFileReader.mFileSize;

        if (compressedSize < 4) {
            throw std::runtime_error("Not enough data to decompress, expected at least 4 "
                                     "bytes (magic number), but got " +
                                     std::to_string(compressedSize));
        }

        uint32_t magicNumber = *(const uint32_t*)&compressedFileReader.data()[0];
        if (magicNumber != ZSTD) {
            std::stringstream sstream;
            sstream << std::hex << magicNumber;
            std::string hex = sstream.str();
            std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
            throw std::runtime_error(
                "Expected ZSTD format to start with appropriate magic "
                "number, instead got: 0x" +
                hex + ", possibly little/big endian issue");
        }

        /* Read the content size from the frame header. For simplicity, we require
         * that it is always present. By default, zstd will write the content size
         * in the header when it is known. If you can't guarantee that the frame
         * content size is always written into the header, either use streaming
         * decompression, or ZSTD_decompressBound().
         */
        auto decompressedFileSize =
            ZSTD_getFrameContentSize(compressedData, compressedSize);
        if (decompressedFileSize == ZSTD_CONTENTSIZE_ERROR) {
            throw std::runtime_error("data is not compressed by zstd");
        }
        if (decompressedFileSize == ZSTD_CONTENTSIZE_UNKNOWN) {
            throw std::runtime_error("decompressed size unknown");
        }

        mDecompressedData = std::unique_ptr<uint8_t>(new uint8_t[decompressedFileSize]);
        if (!mDecompressedData) {
            throw std::runtime_error("Unable to malloc " +
                                     std::to_string(decompressedFileSize) +
                                     " for decompressed file");
        }

        /* Decompress.
         * If you are doing many decompressions, you may want to reuse the context
         * and use ZSTD_decompressDCtx(). If you want to set advanced parameters,
         * use ZSTD_DCtx_setParameter().
         */
        size_t decompressedSize =
            ZSTD_decompress(mDecompressedData.get(), decompressedFileSize, compressedData,
                            compressedSize);
        if (ZSTD_isError(decompressedSize)) {
            throw std::runtime_error(ZSTD_getErrorName(decompressedSize));
        }

        // When zstd knows the content size, it will error if it doesn't match.
        if (decompressedSize != decompressedFileSize) {
            throw std::runtime_error("Content size does not match");
        }

        mDecompressedDataPtr = mDecompressedData.get();
        mFileSize = decompressedSize;
    }

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

#endif

#endif // MMPR_ZSTDFILEREADER_HPP
