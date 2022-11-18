#ifndef MMPR_MODIFIEDPCAPREADER_HPP
#define MMPR_MODIFIEDPCAPREADER_HPP

#include "mmpr/filesystem/reading/FReadFileReader.hpp"
#include "mmpr/filesystem/reading/FileReader.hpp"
#include "mmpr/filesystem/reading/MMapFileReader.hpp"
#include "mmpr/filesystem/reading/ZstdFileReader.hpp"
#include "mmpr/mmpr.hpp"
#include "mmpr/modified_pcap/ModifiedPcapParser.hpp"
#include <filesystem>
#include <stdexcept>

namespace mmpr {

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
    uint16_t getDataLinkType() const override { return mDataLinkType; }
    std::vector<TraceInterface> getTraceInterfaces() const override {
        return std::vector<TraceInterface>();
    }
    TraceInterface getTraceInterface([[maybe_unused]] size_t id) const override {
        return {};
    }

private:
    TReader mReader;
    uint16_t mDataLinkType{101};
};

template class ModifiedPcapReader<FReadFileReader>;
template class ModifiedPcapReader<MMapFileReader>;
template class ModifiedPcapReader<ZstdFileReader>;

typedef ModifiedPcapReader<FReadFileReader> FReadModifiedPcapReader;
typedef ModifiedPcapReader<MMapFileReader> MMModifiedPcapReader;
typedef ModifiedPcapReader<ZstdFileReader> ZstdModifiedPcapReader;

} // namespace mmpr

#endif // MMPR_MODIFIEDPCAPREADER_HPP
