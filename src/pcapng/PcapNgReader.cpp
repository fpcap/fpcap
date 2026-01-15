#include "fpcap/pcapng/PcapNgReader.hpp"

#include <fpcap/MagicNumber.hpp>
#include <fpcap/Packet.hpp>
#include <fpcap/pcapng/PcapNgBlockParser.hpp>
#include <fpcap/pcapng/PcapNgBlockType.hpp>
#include <fpcap/util.hpp>

#include <iostream>
#include <sstream>

namespace fpcap::pcapng {

template <typename TReader>
PcapNgReader<TReader>::PcapNgReader(const std::string& filepath) : mReader(filepath) {
    if (const uint32_t magicNumber = *reinterpret_cast<const uint32_t*>(mReader.data());
        magicNumber != PCAPNG) {
        std::stringstream sstream;
        sstream << std::hex << magicNumber;
        const std::string hex = sstream.str();
        throw std::runtime_error(
            "Expected PcapNG format to start with appropriate magic "
            "number, instead got: 0x" +
            hex + ", possibly little/big endian issue while reading file " + filepath);
    }
}

template <typename TReader>
PcapNgReader<TReader>::PcapNgReader(TReader&& reader)
    : mReader(std::forward<TReader>(reader)) {
    if (const uint32_t magicNumber = *reinterpret_cast<const uint32_t*>(mReader.data());
        magicNumber != PCAPNG) {
        std::stringstream sstream;
        sstream << std::hex << magicNumber;
        const std::string hex = sstream.str();
        throw std::runtime_error(
            "Expected PcapNG format to start with appropriate magic "
            "number, instead got: 0x" +
            hex + ", possibly little/big endian issue while reading file " +
            PcapNgReader::getFilepath());
    }
}

template <typename TReader>
bool PcapNgReader<TReader>::isExhausted() const {
    return mReader.isExhausted();
}

template <typename TReader>
bool PcapNgReader<TReader>::readNextPacket(Packet& packet) {
    if (isExhausted()) {
        // nothing more to read
        return false;
    }

    // make sure there are enough bytes to read
    if (mReader.getSafeToReadSize() < 8) {
        std::cerr << "Error: Expected to read at least one more block (8 bytes at "
                     "least), but there are only "
                  << mReader.getSafeToReadSize() << " bytes left in the file"
                  << std::endl;
        return false;
    }

    uint32_t blockType =
        *reinterpret_cast<const uint32_t*>(&mReader.data()[mReader.mOffset]);
    uint32_t blockTotalLength =
        *reinterpret_cast<const uint32_t*>(&mReader.data()[mReader.mOffset + 4]);

    while (blockType != ENHANCED_PACKET_BLOCK && blockType != PACKET_BLOCK &&
           blockType != SIMPLE_PACKET_BLOCK) {
        if (blockType == SECTION_HEADER_BLOCK) {
            SectionHeaderBlock shb{};
            PcapNgBlockParser::readSHB(&mReader.data()[mReader.mOffset], shb);
            mMetadata.comment = shb.options.comment;
            mMetadata.os = shb.options.os;
            mMetadata.hardware = shb.options.hardware;
            mMetadata.userApplication = shb.options.userApplication;
        } else if (blockType == INTERFACE_DESCRIPTION_BLOCK) {
            InterfaceDescriptionBlock idb{};
            PcapNgBlockParser::readIDB(&mReader.data()[mReader.mOffset], idb);
            mTraceInterfaces.emplace_back(idb.options.name, idb.options.description,
                                          idb.options.filter, idb.options.os,
                                          idb.linkType, idb.options.timestampResolution);
        }

        mReader.mOffset += blockTotalLength;

        if (isExhausted()) {
            // we have reached the end of the file
            return false;
        }

        // make sure there are enough bytes to read
        if (mReader.getSafeToReadSize() < 8) {
            std::cerr << "Error: Expected to read at least one more block (8 bytes at "
                         "least), but there are only "
                      << mReader.getSafeToReadSize() << " bytes left in the file"
                      << std::endl;
            return false;
        }

        // try to read next block type
        blockType = *reinterpret_cast<const uint32_t*>(&mReader.data()[mReader.mOffset]);
        blockTotalLength =
            *reinterpret_cast<const uint32_t*>(&mReader.data()[mReader.mOffset + 4]);
    }

    switch (blockType) {
    case ENHANCED_PACKET_BLOCK: {
        EnhancedPacketBlock epb{};
        PcapNgBlockParser::readEPB(&mReader.data()[mReader.mOffset], epb);
        packet.interfaceIndex = epb.interfaceId;
        packet.dataLinkType = mTraceInterfaces[packet.interfaceIndex].dataLinkType;
        util::calculateTimestamps(
            mTraceInterfaces[packet.interfaceIndex].timestampResolution,
            epb.timestampHigh, epb.timestampLow, &(packet.timestampSeconds),
            &(packet.timestampMicroseconds));
        packet.captureLength = epb.capturePacketLength;
        packet.length = epb.originalPacketLength;
        packet.data = epb.packetData;

        mReader.mOffset += epb.blockTotalLength;
        break;
    }
    case PACKET_BLOCK: {
        PacketBlock pb{};
        PcapNgBlockParser::readPB(&mReader.data()[mReader.mOffset], pb);
        packet.interfaceIndex = pb.interfaceId;
        packet.dataLinkType = mTraceInterfaces[packet.interfaceIndex].dataLinkType;
        util::calculateTimestamps(
            mTraceInterfaces[packet.interfaceIndex].timestampResolution, pb.timestampHigh,
            pb.timestampLow, &(packet.timestampSeconds), &(packet.timestampMicroseconds));
        packet.captureLength = pb.capturePacketLength;
        packet.length = pb.originalPacketLength;
        packet.data = pb.packetData;

        mReader.mOffset += pb.blockTotalLength;
        break;
    }
    case SIMPLE_PACKET_BLOCK: {
        SimplePacketBlock spb{};
        PcapNgBlockParser::readSPB(&mReader.data()[mReader.mOffset], spb);
        // SPB implicitly refers to interface 0
        packet.interfaceIndex = 0;
        packet.dataLinkType =
            mTraceInterfaces.empty() ? 1 : mTraceInterfaces[0].dataLinkType;
        // SPB has no timestamp fields
        packet.timestampSeconds = 0;
        packet.timestampMicroseconds = 0;
        // Captured length is derived from block total length minus header (12) and footer
        // (4)
        packet.captureLength = spb.blockTotalLength - 16;
        packet.length = spb.originalPacketLength;
        packet.data = spb.packetData;

        mReader.mOffset += spb.blockTotalLength;
        break;
    }
    default:;
    }

    return true;
}

template <typename TReader>
uint32_t PcapNgReader<TReader>::readBlock() {
    const auto blockType =
        *reinterpret_cast<const uint32_t*>(&mReader.data()[mReader.mOffset]);
    const auto blockTotalLength =
        *reinterpret_cast<const uint32_t*>(&mReader.data()[mReader.mOffset + 4]);

    switch (blockType) {
    case SECTION_HEADER_BLOCK: {
        SectionHeaderBlock shb{};
        PcapNgBlockParser::readSHB(&mReader.data()[mReader.mOffset], shb);
        mMetadata.comment = shb.options.comment;
        mMetadata.os = shb.options.os;
        mMetadata.hardware = shb.options.hardware;
        mMetadata.userApplication = shb.options.userApplication;
        break;
    }
    case INTERFACE_DESCRIPTION_BLOCK: {
        InterfaceDescriptionBlock idb{};
        PcapNgBlockParser::readIDB(&mReader.data()[mReader.mOffset], idb);
        mTraceInterfaces.emplace_back(idb.options.name, idb.options.description,
                                      idb.options.filter, idb.options.os, idb.linkType,
                                      idb.options.timestampResolution);
        break;
    }
    case ENHANCED_PACKET_BLOCK: {
        EnhancedPacketBlock epb{};
        PcapNgBlockParser::readEPB(&mReader.data()[mReader.mOffset], epb);
        break;
    }
    case PACKET_BLOCK: {
        // deprecated in newer versions of PcapNG
        PacketBlock pb{};
        PcapNgBlockParser::readPB(&mReader.data()[mReader.mOffset], pb);
        break;
    }
    case SIMPLE_PACKET_BLOCK: {
        SimplePacketBlock spb{};
        PcapNgBlockParser::readSPB(&mReader.data()[mReader.mOffset], spb);
        break;
    }
    case NAME_RESOLUTION_BLOCK: {
        FPCAP_WARN("Parsing of Name Resolution Blocks not implemented, skipping\n");
        break;
    }
    case INTERFACE_STATISTICS_BLOCK: {
        InterfaceStatisticsBlock isb{};
        PcapNgBlockParser::readISB(&mReader.data()[mReader.mOffset], isb);
        break;
    }
    case DECRYPTION_SECRETS_BLOCK: {
        FPCAP_WARN("Parsing of Decryption Secrets Blocks not implemented, skipping\n");
        break;
    }
    case CUSTOM_CAN_COPY_BLOCK: {
        FPCAP_WARN("Parsing of Custom (Can Copy) Blocks not implemented, skipping\n");
        break;
    }
    case CUSTOM_DO_NOT_COPY_BLOCK: {
        FPCAP_WARN("Parsing of Custom (Do Not Copy) Blocks not implemented, skipping\n");
        break;
    }
    default: {
        FPCAP_WARN_1("Encountered unknown block type: %u, skipping\n", blockType);
        break;
    }
    }

    // skip to next block
    mReader.mOffset += static_cast<size_t>(blockTotalLength);

    return blockType;
}

template <typename TReader>
TraceInterface PcapNgReader<TReader>::getTraceInterface(const size_t id) const {
    if (id >= mTraceInterfaces.size()) {
        throw std::out_of_range("Trace interface index " + std::to_string(id) +
                                " is out of range");
    }
    return mTraceInterfaces[id];
}

template class PcapNgReader<FReadFileReader>;
template class PcapNgReader<MMapFileReader>;
template class PcapNgReader<ZstdFileReader>;

} // namespace fpcap::pcapng
