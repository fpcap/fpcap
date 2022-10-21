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
    ModifiedPcapReader(const std::string& filepath) : mReader(filepath) {
        modified_pcap::FileHeader fileHeader{};
        ModifiedPcapParser::readFileHeader(mReader.data(), fileHeader);
        mReader.mOffset += 24;
    }

    ModifiedPcapReader(TReader&& reader) : mReader(std::forward<TReader>(reader)) {
        modified_pcap::FileHeader fileHeader{};
        ModifiedPcapParser::readFileHeader(mReader.data(), fileHeader);
        mReader.mOffset += 24;
    }

    bool isExhausted() const override { return mReader.isExhausted(); }

    bool readNextPacket(Packet& packet) override {
        if (isExhausted()) {
            // nothing more to read
            return false;
        }

        // make sure there are enough bytes to read
        if (mReader.getSafeToReadSize() < 24) {
            throw std::runtime_error(
                "Expected to read at least one more raw packet record (24 bytes "
                "at least), but there are only " +
                std::to_string(mReader.getSafeToReadSize()) + " bytes left in the file");
        }

        modified_pcap::PacketRecord packetRecord{};
        ModifiedPcapParser::readPacketRecord(&mReader.data()[mReader.mOffset],
                                             packetRecord);
        packet.timestampSeconds = packetRecord.timestampSeconds;
        packet.captureLength = packetRecord.captureLength;
        packet.length = packetRecord.length;
        packet.data = packetRecord.data;

        mReader.mOffset += 24 + packetRecord.captureLength;

        return true;
    }

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

typedef ModifiedPcapReader<FReadFileReader> FReadModifiedPcapReader;
typedef ModifiedPcapReader<MMapFileReader> MMModifiedPcapReader;
typedef ModifiedPcapReader<ZstdFileReader> ZstdModifiedPcapReader;

} // namespace mmpr

#endif // MMPR_MODIFIEDPCAPREADER_HPP
