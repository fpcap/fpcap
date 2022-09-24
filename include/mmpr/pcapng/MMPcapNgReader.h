#ifndef MMPR_MMPCAPNGREADER_H
#define MMPR_MMPCAPNGREADER_H

#include "mmpr/filesystem/MMapFileReader.h"
#include "mmpr/pcapng/PcapNgReader.h"

namespace mmpr {

class MMPcapNgReader : public PcapNgReader {
public:
    explicit MMPcapNgReader(const std::string& filepath)
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
    MMapFileReader mReader;
};

} // namespace mmpr

#endif // MMPR_MMPCAPNGREADER_H
