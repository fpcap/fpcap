#ifndef MMPR_FREADPCAPNGREADER_H
#define MMPR_FREADPCAPNGREADER_H

#include "mmpr/filesystem/FReadFileReader.h"
#include "mmpr/filesystem/MMapFileReader.h"
#include "mmpr/pcapng/PcapNgReader.h"

namespace mmpr {

class FReadPcapNgReader : public PcapNgReader {
public:
    explicit FReadPcapNgReader(const std::string& filepath)
        : PcapNgReader(filepath), mReader(filepath) {
        uint32_t magicNumber = util::read32bitsFromFile(filepath);
        if (magicNumber != MMPR_MAGIC_NUMBER_PCAPNG) {
            std::stringstream sstream;
            sstream << std::hex << magicNumber;
            std::string hex = sstream.str();
            std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
            throw std::runtime_error(
                "Expected PcapNG format to start with appropriate magic "
                "number, instead got: 0x" +
                hex + ", possibly little/big endian issue");
        }
    };

    bool readNextPacket(Packet& packet) override;
    uint32_t readBlock() override;

    bool isExhausted() const override { return mReader.isExhausted(); }
    size_t getFileSize() const override { return mReader.mFileSize; }
    std::string getFilepath() const override { return mReader.mFilePath; }
    size_t getCurrentOffset() const override { return mReader.mOffset; }

private:
    FReadFileReader mReader;
};

} // namespace mmpr

#endif // MMPR_FREADPCAPNGREADER_H
