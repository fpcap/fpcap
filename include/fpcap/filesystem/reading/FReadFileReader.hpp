#ifndef FPCAP_FREADFILEREADER_HPP
#define FPCAP_FREADFILEREADER_HPP

#include "FileReader.hpp"
#include <cstring>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <locale.h>

namespace fpcap {

class FReadFileReader : public FileReader {
public:
    FReadFileReader(const std::string& filepath);

    const uint8_t* data() const override { return mFileContentPtr; }

private:
    std::unique_ptr<uint8_t[]> mFileContent;
    const uint8_t* mFileContentPtr;
};

} // namespace fpcap

#endif // FPCAP_FREADFILEREADER_HPP
