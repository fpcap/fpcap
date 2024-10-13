#ifndef FPCAP_MODIFIEDPCAPREADER_HPP
#define FPCAP_MODIFIEDPCAPREADER_HPP

#include <fpcap/filesystem/FReadFileReader.hpp>
#include <fpcap/filesystem/FileReader.hpp>
#include <fpcap/filesystem/MMapFileReader.hpp>
#include <fpcap/filesystem/ZstdFileReader.hpp>
#include <fpcap/Packet.hpp>
#include <fpcap/filesystem/Reader.hpp>

#include <filesystem>

namespace fpcap::modified_pcap {
template <typename TReader>
class ModifiedPcapReader final : public Reader {
    static_assert(std::is_base_of_v<FileReader, TReader>,
                  "TReader must be a subclass of FileReader");

public:
    explicit ModifiedPcapReader(const std::string& filepath);

    explicit ModifiedPcapReader(TReader&& reader);

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
    uint16_t mLinkType{0};
};

typedef ModifiedPcapReader<FReadFileReader> FReadModifiedPcapReader;
typedef ModifiedPcapReader<MMapFileReader> MMModifiedPcapReader;
typedef ModifiedPcapReader<ZstdFileReader> ZstdModifiedPcapReader;
} // namespace fpcap::modified_pcap

#endif // FPCAP_MODIFIEDPCAPREADER_HPP
