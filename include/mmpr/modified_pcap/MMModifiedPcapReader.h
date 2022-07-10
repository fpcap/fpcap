#ifndef MMPR_MMRAWREADER_H
#define MMPR_MMRAWREADER_H

#include "mmpr/mmpr.h"
#include "mmpr/modified_pcap/ModifiedPcapReader.h"
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace mmpr {
class MMModifiedPcapReader : public ModifiedPcapReader {
public:
    explicit MMModifiedPcapReader(const std::string& filepath);

    void open() override;
    bool isExhausted() const override;
    bool readNextPacket(Packet& packet) override;
    void close() override;

    size_t getFileSize() const override { return mFileSize; }
    size_t getCurrentOffset() const override { return mOffset; }

private:
    int mFileDescriptor{0};
    size_t mFileSize{0};
    size_t mMappedSize{0};
    const uint8_t* mMappedMemory{nullptr};
    size_t mOffset{0};
};
} // namespace mmpr

#endif // MMPR_MMRAWREADER_H
