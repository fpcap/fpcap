#ifndef MMPR_ZSTDPCAPNGREADER_H
#define MMPR_ZSTDPCAPNGREADER_H

#include <mmpr/mmpr.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace mmpr {
class ZstdPcapNgReader {
public:
    explicit ZstdPcapNgReader(const std::string& filepath);

    void open();
    bool isExhausted() const;
    bool readNextPacket(Packet& packet);
    uint32_t readBlock();
    void close();
    size_t getFileSize() const { return mFileSize; };

private:
    std::string mFilepath;
    size_t mFileSize{0};
    const uint8_t* mData{nullptr};
    size_t mOffset{0};
};
} // namespace mmpr

#endif // MMPR_ZSTDPCAPNGREADER_H
