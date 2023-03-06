#ifndef MMPR_PCAPREADER_HPP
#define MMPR_PCAPREADER_HPP

#include "mmpr/filesystem/reading/FReadFileReader.hpp"
#include "mmpr/filesystem/reading/MMapFileReader.hpp"
#include "mmpr/filesystem/reading/ZstdFileReader.hpp"
#include "mmpr/mmpr.hpp"
#include "mmpr/pcap/PcapParser.hpp"
#include "mmpr/util.hpp"
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>

namespace mmpr {

template <typename TReader>
class PcapReader : public Reader {
    static_assert(std::is_base_of<FileReader, TReader>::value,
                  "TReader must be a subclass of FileReader");

public:
    PcapReader(const std::string& filepath);

    PcapReader(TReader&& reader);

    bool isExhausted() const override;

    bool readNextPacket(Packet& packet) override;

    size_t getFileSize() const override { return mReader.mFileSize; }
    std::string getFilepath() const override { return mReader.mFilepath; }
    size_t getCurrentOffset() const override { return mReader.mOffset; }
    std::vector<TraceInterface> getTraceInterfaces() const override {
        return std::vector<TraceInterface>();
    }
    TraceInterface getTraceInterface([[maybe_unused]] size_t id) const override {
        return {};
    }

private:
    TReader mReader;
    uint16_t mDataLinkType{0};
    pcap::FileHeader::TimestampFormat mTimestampFormat{pcap::FileHeader::MICROSECONDS};
};

typedef PcapReader<FReadFileReader> FReadPcapReader;
typedef PcapReader<MMapFileReader> MMPcapReader;
typedef PcapReader<ZstdFileReader> ZstdPcapReader;

} // namespace mmpr

#endif // MMPR_PCAPREADER_HPP
