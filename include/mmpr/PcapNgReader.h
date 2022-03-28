#ifndef MMPR_PCAPNGREADER_H
#define MMPR_PCAPNGREADER_H

#include <mmpr/mmpr.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace mmpr {
class PcapNgReader {
public:
    explicit PcapNgReader(const std::string& filepath);

    void open();
    bool isExhausted() const;
    bool readNextPacket(Packet& packet);
    uint32_t readBlock();
    void close();
    size_t getFileSize() const { return mFileSize; }

private:
    std::string mFilepath;
    int mFileDescriptor{0};
    size_t mFileSize{0};
    size_t mMappedSize{0};
    const uint8_t* mMappedMemory{nullptr};
    size_t mOffset{0};
};
} // namespace mmpr

#endif // MMPR_PCAPNGREADER_H
