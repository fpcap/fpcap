#ifndef MMPR_MMRAWREADER_H
#define MMPR_MMRAWREADER_H

#include "mmpr/filesystem/MMapFileReader.h"
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

    bool isExhausted() const override { return mReader.isExhausted(); };
    bool readNextPacket(Packet& packet) override;

    size_t getFileSize() const override { return mReader.mFileSize; }
    size_t getCurrentOffset() const override { return mReader.mOffset; }
    std::string getFilepath() const override { return mReader.mFilePath; }

private:
    MMapFileReader mReader;
};
} // namespace mmpr

#endif // MMPR_MMRAWREADER_H
