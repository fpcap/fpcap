#ifndef FPCAP_MODIFIEDPCAPREADER_HPP
#define FPCAP_MODIFIEDPCAPREADER_HPP

#include "fpcap/fpcap.hpp"
#include "fpcap/filesystem/reading/FReadFileReader.hpp"
#include "fpcap/filesystem/reading/FileReader.hpp"
#include "fpcap/filesystem/reading/MMapFileReader.hpp"
#include "fpcap/filesystem/reading/ZstdFileReader.hpp"
#include "fpcap/modified_pcap/ModifiedPcapParser.hpp"
#include <filesystem>
#include <stdexcept>

namespace fpcap {

template <typename TReader>
class ModifiedPcapReader : public Reader {
    static_assert(std::is_base_of<FileReader, TReader>::value,
                  "TReader must be a subclass of FileReader");

public:
    ModifiedPcapReader(const std::string& filepath);

    ModifiedPcapReader(TReader&& reader);

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

} // namespace fpcap

#endif // FPCAP_MODIFIEDPCAPREADER_HPP
