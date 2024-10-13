#ifndef FPCAP_FREADFILEREADER_HPP
#define FPCAP_FREADFILEREADER_HPP

#include <fpcap/filesystem/FileReader.hpp>

#include <filesystem>
#include <memory>

namespace fpcap {
class FReadFileReader final : public FileReader {
public:
    explicit FReadFileReader(const std::string& filepath);

    const uint8_t* data() const override { return mFileContentPtr; }

private:
    std::unique_ptr<uint8_t[]> mFileContent;
    const uint8_t* mFileContentPtr;
};
} // namespace fpcap

#endif // FPCAP_FREADFILEREADER_HPP
