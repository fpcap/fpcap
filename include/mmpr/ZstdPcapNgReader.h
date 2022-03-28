#ifndef MMPR_ZSTDPCAPNGREADER_H
#define MMPR_ZSTDPCAPNGREADER_H

#include <mmpr/mmpr.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace mmpr {
class ZstdPcapNgReader : public PcapNgReader {
public:
    explicit ZstdPcapNgReader(const std::string& filepath);

    void open() override;
    bool isExhausted() const override;
    bool readNextPacket(Packet& packet) override;
    uint32_t readBlock() override;
    void close() override;

    size_t getFileSize() const override { return mFileSize; };
    size_t getCurrentOffset() const override { return mOffset; };
    int getDataLinkType() const override { return mDataLinkType; };

private:
    size_t mFileSize{0};
    const uint8_t* mData{nullptr};
    size_t mOffset{0};
    int mDataLinkType{-1};
};
} // namespace mmpr

#endif // MMPR_ZSTDPCAPNGREADER_H
