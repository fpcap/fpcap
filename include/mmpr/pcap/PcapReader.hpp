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

namespace mmpr {

template <typename TReader>
class PcapReader : public Reader {
    static_assert(std::is_base_of<FileReader, TReader>::value,
                  "TReader must be a subclass of FileReader");

public:
    PcapReader(const std::string& filepath) : mReader(filepath) {
        pcap::FileHeader fileHeader{};
        PcapParser::readFileHeader(mReader.data(), fileHeader);
        mDataLinkType = fileHeader.linkType;
        mTimestampFormat = fileHeader.timestampFormat;
        mReader.mOffset += 24;
    }

    PcapReader(TReader&& reader) : mReader(std::forward<TReader>(reader)) {
        pcap::FileHeader fileHeader{};
        PcapParser::readFileHeader(mReader.data(), fileHeader);
        mDataLinkType = fileHeader.linkType;
        mTimestampFormat = fileHeader.timestampFormat;
        mReader.mOffset += 24;
    }

    bool isExhausted() const { return mReader.isExhausted(); }

    bool readNextPacket(Packet& packet) {
        if (isExhausted()) {
            // nothing more to read
            return false;
        }

        // make sure there are enough bytes to read
        if (mReader.getSafeToReadSize() < 16) {
            throw std::runtime_error(
                "Expected to read at least one more packet record (16 bytes "
                "at least), but there are only " +
                std::to_string(mReader.getSafeToReadSize()) + " bytes left in the file");
        }

        pcap::PacketRecord packetRecord{};
        PcapParser::readPacketRecord(&mReader.data()[mReader.mOffset], packetRecord);
        packet.timestampSeconds = packetRecord.timestampSeconds;
        packet.timestampMicroseconds = mTimestampFormat == pcap::FileHeader::MICROSECONDS
                                           ? packetRecord.timestampSubSeconds
                                           : packetRecord.timestampSubSeconds / 1000;
        packet.captureLength = packetRecord.captureLength;
        packet.length = packetRecord.length;
        packet.data = packetRecord.data;

        mReader.mOffset += 16 + packetRecord.captureLength;

        return true;
    }

    size_t getFileSize() const { return mReader.mFileSize; }
    std::string getFilepath() const override { return mReader.mFilepath; }
    size_t getCurrentOffset() const { return mReader.mOffset; }
    uint16_t getDataLinkType() const override { return mDataLinkType; }
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
#if MMPR_USE_ZSTD
typedef PcapReader<ZstdFileReader> ZstdPcapReader;
#endif

} // namespace mmpr

#endif // MMPR_PCAPREADER_HPP
