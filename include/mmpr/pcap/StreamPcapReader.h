#ifndef MMPR_STREAMPCAPREADER_H
#define MMPR_STREAMPCAPREADER_H

#include "mmpr/filesystem/StreamFileReader.h"
#include "mmpr/mmpr.h"
#include "mmpr/pcap/PcapReader.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace mmpr {

class StreamPcapReader : public PcapReader {

public:
    explicit StreamPcapReader(const std::string& filepath);

    bool isExhausted() const override { return mReader.isExhausted(); };
    bool readNextPacket(Packet& packet) override;

    size_t getFileSize() const override { return mReader.mFileSize; }
    size_t getCurrentOffset() const override { return mReader.mOffset; }
    std::string getFilepath() const override { return mReader.mFilePath; }

private:
    StreamFileReader mReader;
    FileHeader::TimestampFormat mTimestampFormat{FileHeader::MICROSECONDS};
};

} // namespace mmpr

#endif // MMPR_STREAMPCAPREADER_H
