#ifndef MMPR_PCAPNGREADER_HPP
#define MMPR_PCAPNGREADER_HPP

#include "mmpr/filesystem/reading/FReadFileReader.hpp"
#include "mmpr/filesystem/reading/FileReader.hpp"
#include "mmpr/filesystem/reading/MMapFileReader.hpp"
#include "mmpr/filesystem/reading/ZstdFileReader.hpp"
#include "mmpr/mmpr.hpp"
#include "mmpr/pcapng/PcapNgBlockParser.hpp"
#include "mmpr/util.hpp"
#include <algorithm>
#include <filesystem>
#include <stdexcept>

namespace mmpr {

template <typename TReader>
class PcapNgReader : public Reader {
    static_assert(std::is_base_of<FileReader, TReader>::value,
                  "TReader must be a subclass of FileReader");

public:
    PcapNgReader(const std::string& filepath);

    PcapNgReader(TReader&& reader);

    bool isExhausted() const override;

    bool readNextPacket(Packet& packet) override;

    /**
     * 3.1.  General Block Structure
     *
     *                        1                   2                   3
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 0 |                          Block Type                           |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 4 |                      Block Total Length                       |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 8 /                          Block Body                           /
     *   /              variable length, padded to 32 bits               /
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |                      Block Total Length                       |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    uint32_t readBlock() override;

    size_t getFileSize() const override { return mReader.mFileSize; }

    std::string getFilepath() const override { return mReader.mFilepath; }

    size_t getCurrentOffset() const override { return mReader.mOffset; }

    uint16_t getDataLinkType() const override { return mDataLinkType; }

    std::string getComment() const override { return mMetadata.comment; }

    std::string getOS() const override { return mMetadata.os; }

    std::string getHardware() const override { return mMetadata.hardware; }

    std::string getUserApplication() const override { return mMetadata.userApplication; }

    std::vector<TraceInterface> getTraceInterfaces() const override {
        return mTraceInterfaces;
    }

    TraceInterface getTraceInterface(size_t id) const override;

private:
    TReader mReader;
    uint16_t mDataLinkType{0};
    std::vector<TraceInterface> mTraceInterfaces;

    struct PcapNgMetadata {
        std::string comment;
        std::string os;
        std::string hardware;
        std::string userApplication;
        // TODO support if_tsresol per interface
        uint32_t timestampResolution{1000000 /* 10^6 */};
    } mMetadata{};
};

typedef PcapNgReader<FReadFileReader> FReadPcapNgReader;
typedef PcapNgReader<MMapFileReader> MMPcapNgReader;
typedef PcapNgReader<ZstdFileReader> ZstdPcapNgReader;

} // namespace mmpr

#endif // MMPR_PCAPNGREADER_HPP
