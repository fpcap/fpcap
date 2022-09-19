#ifndef MMPR_FREADPCAPREADER_H
#define MMPR_FREADPCAPREADER_H

#include "mmpr/mmpr.h"
#include "mmpr/pcap/PcapReader.h"
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace mmpr {
class GzipPcapReader : public PcapReader {
public:
    explicit GzipPcapReader(const std::string& filepath);
    ~GzipPcapReader() {
        if (mData != nullptr) {
            delete[] mData;
        }
    }

    void open() override;
    bool isExhausted() const override { return mOffset >= mFileSize; };
    bool readNextPacket(Packet& packet) override;
    void close() override{};

    size_t getFileSize() const override { return mFileSize; };
    size_t getCurrentOffset() const override { return mOffset; };

private:
    size_t mFileSize{0};
    const uint8_t* mData{nullptr};
    size_t mOffset{0};
};
} // namespace mmpr

#endif // MMPR_FREADPCAPREADER_H
