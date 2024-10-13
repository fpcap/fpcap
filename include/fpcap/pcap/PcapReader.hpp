#ifndef FPCAP_PCAPREADER_HPP
#define FPCAP_PCAPREADER_HPP

#include <fpcap/filesystem/Reader.hpp>
#include <fpcap/TraceInterface.hpp>
#include <fpcap/filesystem/FReadFileReader.hpp>
#include <fpcap/filesystem/MMapFileReader.hpp>
#include <fpcap/filesystem/ZstdFileReader.hpp>
#include <fpcap/pcap/PcapFileHeader.hpp>

#include <string>

namespace fpcap::pcap {
template <typename TReader>
class PcapReader final : public Reader {
    static_assert(std::is_base_of_v<FileReader, TReader>,
                  "TReader must be a subclass of FileReader");

public:
    explicit PcapReader(const std::string& filepath);

    explicit PcapReader(TReader&& reader);

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
} // namespace fpcap::pcap

#endif // FPCAP_PCAPREADER_HPP
