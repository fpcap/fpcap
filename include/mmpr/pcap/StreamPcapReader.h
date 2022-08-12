#ifndef MMPR_STREAMPCAPREADER_H
#define MMPR_STREAMPCAPREADER_H

#include "mmpr/mmpr.h"
#include "mmpr/pcap/PcapReader.h"
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <fstream>

namespace mmpr {
class StreamPcapReader : public PcapReader {
public:
    explicit StreamPcapReader(const std::string& filepath);

    void open() override;
    bool isExhausted() const override;
    bool readNextPacket(Packet& packet) override;
    void close() override;

    size_t getFileSize() const override { return mFileSize; }
    size_t getCurrentOffset() const override { return mOffset; }

private:
    size_t mFileSize{0};
    std::ifstream mStream;
    size_t mOffset{0};
    FileHeader::TimestampFormat mTimestampFormat{FileHeader::MICROSECONDS};
};
} // namespace mmpr

#endif // MMPR_STREAMPCAPREADER_H
