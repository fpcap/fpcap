#ifndef MMPR_MMPCAPREADER_H
#define MMPR_MMPCAPREADER_H

#include "mmpr/filesystem/MMapFileReader.h"
#include "mmpr/mmpr.h"
#include "mmpr/pcap/PcapReader.h"
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace mmpr {

class MMPcapReader : public PcapReader {
public:
    explicit MMPcapReader(const std::string& filepath);

    bool isExhausted() const override { return mReader.isExhausted(); };
    bool readNextPacket(Packet& packet) override;

    size_t getFileSize() const override { return mReader.mFileSize; }
    size_t getCurrentOffset() const override { return mReader.mOffset; }
    std::string getFilepath() const override { return mReader.mFilePath; }

private:
    MMapFileReader mReader;
    FileHeader::TimestampFormat mTimestampFormat{FileHeader::MICROSECONDS};
};

} // namespace mmpr

#endif // MMPR_MMPCAPREADER_H
