#ifndef MMPR_ZSTDPCAPNGREADER_H
#define MMPR_ZSTDPCAPNGREADER_H

#include "MMPcapNgReader.h"
#include "mmpr/filesystem/ZstdFileReader.h"
#include "mmpr/pcapng/PcapNgReader.h"

namespace mmpr {

class ZstdPcapNgReader : public PcapNgReader {
public:
    explicit ZstdPcapNgReader(const std::string& filepath)
        : PcapNgReader(filepath), mReader(filepath) {}

    bool readNextPacket(Packet& packet) override;
    uint32_t readBlock() override;

    bool isExhausted() const override { return mReader.isExhausted(); }
    size_t getFileSize() const override { return mReader.mFileSize; }
    std::string getFilepath() const override { return mReader.mFilePath; }
    size_t getCurrentOffset() const override { return mReader.mOffset; }

private:
    ZstdFileReader mReader;
};

} // namespace mmpr

#endif // MMPR_ZSTDPCAPNGREADER_H
