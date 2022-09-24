#ifndef MMPR_PCAPREADER_H
#define MMPR_PCAPREADER_H

#include "mmpr/filesystem/FReadFileReader.h"
#include "mmpr/filesystem/MMapFileReader.h"
#include "mmpr/mmpr.h"
#include "mmpr/pcap/PcapParser.h"
#include "mmpr/util.h"
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
        if (filepath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!std::filesystem::exists(filepath)) {
            throw std::runtime_error("Cannot find file " +
                                     std::filesystem::absolute(filepath).string());
        }

        uint32_t magicNumber = util::read32bitsFromFile(filepath);
        if (magicNumber != MMPR_MAGIC_NUMBER_PCAP_MICROSECONDS &&
            magicNumber != MMPR_MAGIC_NUMBER_PCAP_NANOSECONDS) {
            std::stringstream sstream;
            sstream << std::hex << magicNumber;
            std::string hex = sstream.str();
            std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
            throw std::runtime_error(
                "Expected PCAP format to start with appropriate magic "
                "numbers, instead got: 0x" +
                hex + ", possibly little/big endian issue");
        }

        FileHeader fileHeader{};
        PcapParser::readFileHeader(mReader.data(), fileHeader);
        mDataLinkType = fileHeader.linkType;
        mTimestampFormat = fileHeader.timestampFormat;
        mReader.mOffset += 24;
    };

    bool isExhausted() const { return mReader.isExhausted(); };

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

        PacketRecord packetRecord{};
        PcapParser::readPacketRecord(&mReader.data()[mReader.mOffset], packetRecord);
        packet.timestampSeconds = packetRecord.timestampSeconds;
        packet.timestampMicroseconds = mTimestampFormat == FileHeader::MICROSECONDS
                                           ? packetRecord.timestampSubSeconds
                                           : packetRecord.timestampSubSeconds / 1000;
        packet.captureLength = packetRecord.captureLength;
        packet.length = packetRecord.length;
        packet.data = packetRecord.data;

        mReader.mOffset += 16 + packetRecord.captureLength;

        return true;
    };

    size_t getFileSize() const { return mReader.mFileSize; };
    std::string getFilepath() const override { return mReader.mFilePath; };
    size_t getCurrentOffset() const { return mReader.mOffset; };
    uint16_t getDataLinkType() const override { return mDataLinkType; };
    std::vector<TraceInterface> getTraceInterfaces() const override {
        return std::vector<TraceInterface>();
    }
    TraceInterface getTraceInterface([[maybe_unused]] size_t id) const override {
        return {};
    }

private:
    TReader mReader;
    uint16_t mDataLinkType{0};
    FileHeader::TimestampFormat mTimestampFormat{FileHeader::MICROSECONDS};
};

typedef PcapReader<FReadFileReader> FReadPcapReader;
typedef PcapReader<MMapFileReader> MMPcapReader;

} // namespace mmpr

#endif // MMPR_PCAPREADER_H
