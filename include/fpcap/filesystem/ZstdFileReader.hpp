#ifndef FPCAP_ZSTDFILEREADER_HPP
#define FPCAP_ZSTDFILEREADER_HPP

#include <fpcap/filesystem/FileReader.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace fpcap {
class ZstdFileReader final : public FileReader {
public:
    explicit ZstdFileReader(const std::string& filepath);

    ZstdFileReader(ZstdFileReader&& other) noexcept;

    const uint8_t* data() const override { return mDecompressedDataPtr; }

private:
    std::unique_ptr<uint8_t> mDecompressedData;
    const uint8_t* mDecompressedDataPtr;
};
} // namespace fpcap

#endif // FPCAP_ZSTDFILEREADER_HPP
