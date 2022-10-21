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
    PcapNgReader(const std::string& filepath) : mReader(filepath) {
        uint32_t magicNumber = *(uint32_t*)mReader.data();
        if (magicNumber != PCAPNG) {
            std::stringstream sstream;
            sstream << std::hex << magicNumber;
            std::string hex = sstream.str();
            std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
            throw std::runtime_error(
                "Expected PcapNG format to start with appropriate magic "
                "number, instead got: 0x" +
                hex + ", possibly little/big endian issue while reading file " +
                filepath);
        }
    }

    PcapNgReader(TReader&& reader) : mReader(std::forward<TReader>(reader)) {
        uint32_t magicNumber = *(uint32_t*)mReader.data();
        if (magicNumber != PCAPNG) {
            std::stringstream sstream;
            sstream << std::hex << magicNumber;
            std::string hex = sstream.str();
            std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
            throw std::runtime_error(
                "Expected PcapNG format to start with appropriate magic "
                "number, instead got: 0x" +
                hex + ", possibly little/big endian issue while reading file " +
                getFilepath());
        }
    }

    bool isExhausted() const override { return mReader.isExhausted(); }

    bool readNextPacket(Packet& packet) override {
        if (isExhausted()) {
            // nothing more to read
            return false;
        }

        // make sure there are enough bytes to read
        if (mReader.getSafeToReadSize() < 8) {
            throw std::runtime_error(
                "Expected to read at least one more block (8 bytes at "
                "least), but there are only " +
                std::to_string(mReader.getSafeToReadSize()) + " bytes left in the file");
        }

        uint32_t blockType = *(uint32_t*)&mReader.data()[mReader.mOffset];
        uint32_t blockTotalLength = *(uint32_t*)&mReader.data()[mReader.mOffset + 4];

        // TODO add support for Simple Packet Blocks
        while (blockType != MMPR_ENHANCED_PACKET_BLOCK &&
               blockType != MMPR_PACKET_BLOCK) {
            if (blockType == MMPR_SECTION_HEADER_BLOCK) {
                pcapng::SectionHeaderBlock shb{};
                PcapNgBlockParser::readSHB(&mReader.data()[mReader.mOffset], shb);
                mMetadata.comment = shb.options.comment;
                mMetadata.os = shb.options.os;
                mMetadata.hardware = shb.options.hardware;
                mMetadata.userApplication = shb.options.userApplication;
            } else if (blockType == MMPR_INTERFACE_DESCRIPTION_BLOCK) {
                pcapng::InterfaceDescriptionBlock idb{};
                PcapNgBlockParser::readIDB(&mReader.data()[mReader.mOffset], idb);
                mDataLinkType = idb.linkType;
                mMetadata.timestampResolution = idb.options.timestampResolution;
                mTraceInterfaces.emplace_back(idb.options.name, idb.options.description,
                                              idb.options.filter, idb.options.os);
            }

            mReader.mOffset += blockTotalLength;

            if (isExhausted()) {
                // we have reached the end of the file
                return false;
            }

            // make sure there are enough bytes to read
            if (mReader.getSafeToReadSize() < 8) {
                throw std::runtime_error(
                    "Expected to read at least one more block (8 bytes at "
                    "least), but there are only " +
                    std::to_string(mReader.getSafeToReadSize()) +
                    " bytes left in the file");
            }

            // try to read next block type
            blockType = *(const uint32_t*)&mReader.data()[mReader.mOffset];
            blockTotalLength = *(const uint32_t*)&mReader.data()[mReader.mOffset + 4];
        }

        switch (blockType) {
        case MMPR_ENHANCED_PACKET_BLOCK: {
            pcapng::EnhancedPacketBlock epb{};
            PcapNgBlockParser::readEPB(&mReader.data()[mReader.mOffset], epb);
            util::calculateTimestamps(mMetadata.timestampResolution, epb.timestampHigh,
                                      epb.timestampLow, &(packet.timestampSeconds),
                                      &(packet.timestampMicroseconds));
            packet.captureLength = epb.capturePacketLength;
            packet.length = epb.originalPacketLength;
            packet.data = epb.packetData;
            packet.interfaceIndex = epb.interfaceId;

            mReader.mOffset += epb.blockTotalLength;
            break;
        }
        case MMPR_PACKET_BLOCK: {
            pcapng::PacketBlock pb{};
            PcapNgBlockParser::readPB(&mReader.data()[mReader.mOffset], pb);
            util::calculateTimestamps(mMetadata.timestampResolution, pb.timestampHigh,
                                      pb.timestampLow, &(packet.timestampSeconds),
                                      &(packet.timestampMicroseconds));
            packet.captureLength = pb.capturePacketLength;
            packet.length = pb.originalPacketLength;
            packet.data = pb.packetData;
            packet.interfaceIndex = pb.interfaceId;

            mReader.mOffset += pb.blockTotalLength;
            break;
        }
        }

        return true;
    }

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
    uint32_t readBlock() override {
        const auto blockType = *(const uint32_t*)&mReader.data()[mReader.mOffset];
        const auto blockTotalLength =
            *(const uint32_t*)&mReader.data()[mReader.mOffset + 4];

        switch (blockType) {
        case MMPR_SECTION_HEADER_BLOCK: {
            pcapng::SectionHeaderBlock shb{};
            PcapNgBlockParser::readSHB(&mReader.data()[mReader.mOffset], shb);
            mMetadata.comment = shb.options.comment;
            mMetadata.os = shb.options.os;
            mMetadata.hardware = shb.options.hardware;
            mMetadata.userApplication = shb.options.userApplication;
            break;
        }
        case MMPR_INTERFACE_DESCRIPTION_BLOCK: {
            pcapng::InterfaceDescriptionBlock idb{};
            PcapNgBlockParser::readIDB(&mReader.data()[mReader.mOffset], idb);
            mDataLinkType = idb.linkType;
            mMetadata.timestampResolution = idb.options.timestampResolution;
            mTraceInterfaces.emplace_back(idb.options.name, idb.options.description,
                                          idb.options.filter, idb.options.os);
            break;
        }
        case MMPR_ENHANCED_PACKET_BLOCK: {
            pcapng::EnhancedPacketBlock epb{};
            PcapNgBlockParser::readEPB(&mReader.data()[mReader.mOffset], epb);
            break;
        }
        case MMPR_PACKET_BLOCK: {
            // deprecated in newer versions of PcapNG
            pcapng::PacketBlock pb{};
            PcapNgBlockParser::readPB(&mReader.data()[mReader.mOffset], pb);
            break;
        }
        case MMPR_SIMPLE_PACKET_BLOCK: {
            MMPR_WARN("Parsing of Simple Packet Blocks not implemented, skipping\n");
            break;
        }
        case MMPR_NAME_RESOLUTION_BLOCK: {
            MMPR_WARN("Parsing of Name Resolution Blocks not implemented, skipping\n");
            break;
        }
        case MMPR_INTERFACE_STATISTICS_BLOCK: {
            pcapng::InterfaceStatisticsBlock isb{};
            PcapNgBlockParser::readISB(&mReader.data()[mReader.mOffset], isb);
            break;
        }
        case MMPR_DECRYPTION_SECRETS_BLOCK: {
            MMPR_WARN("Parsing of Decryption Secrets Blocks not implemented, skipping\n");
            break;
        }
        case MMPR_CUSTOM_CAN_COPY_BLOCK: {
            MMPR_WARN("Parsing of Custom (Can Copy) Blocks not implemented, skipping\n");
            break;
        }
        case MMPR_CUSTOM_DO_NOT_COPY_BLOCK: {
            MMPR_WARN(
                "Parsing of Custom (Do Not Copy) Blocks not implemented, skipping\n");
            break;
        }
        default: {
            MMPR_WARN_1("Encountered unknown block type: %u, skipping\n", blockType);
            break;
        }
        }

        // skip to next block
        mReader.mOffset += (size_t)blockTotalLength;

        return blockType;
    }

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

    TraceInterface getTraceInterface(size_t id) const override {
        if (id >= mTraceInterfaces.size()) {
            throw std::out_of_range("Trace interface index " + std::to_string(id) +
                                    " is out of range");
        }
        return mTraceInterfaces[id];
    }

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
