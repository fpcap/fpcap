#ifndef MMPR_MMPCAPNGREADER_H
#define MMPR_MMPCAPNGREADER_H

#include <mmpr/mmpr.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace mmpr {
class MMPcapNgReader : PcapNgReader {
public:
    explicit MMPcapNgReader(const std::string& filepath) : PcapNgReader(filepath) {};

    void open() override;
    bool isExhausted() const override;
    bool readNextPacket(Packet& packet) override;
    uint32_t readBlock() override;
    void close() override;

    size_t getFileSize() const override { return mFileSize; }
    size_t getCurrentOffset() const override { return mOffset; }
    int getDataLinkType() const override { return mDataLinkType; }

private:
    int mFileDescriptor{0};
    size_t mFileSize{0};
    size_t mMappedSize{0};
    const uint8_t* mMappedMemory{nullptr};
    size_t mOffset{0};
    int mDataLinkType{-1};
};
} // namespace mmpr

#endif // MMPR_MMPCAPNGREADER_H
