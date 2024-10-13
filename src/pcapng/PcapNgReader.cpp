#include "fpcap/pcapng/PcapNgReader.hpp"

#include <fpcap/pcapng/PcapNgBlockParser.hpp>
#include <fpcap/util.hpp>
#include <fpcap/pcapng/PcapNgBlockType.hpp>
#include <fpcap/MagicNumber.hpp>
#include <fpcap/Packet.hpp>

#include <iostream>
#include <sstream>

namespace fpcap::pcapng {

template <typename TReader>
PcapNgReader<TReader>::PcapNgReader(const std::string& filepath)
    : mReader(filepath) {
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

    uint32_t blockType = *reinterpret_cast<const uint32_t*>(&mReader.data()[mReader.
        mOffset]);
    uint32_t blockTotalLength = *reinterpret_cast<const uint32_t*>(&mReader.data()[
        mReader.mOffset + 4]);

    // TODO add support for Simple Packet Blocks
    while (blockType != ENHANCED_PACKET_BLOCK && blockType != PACKET_BLOCK) {
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
            mMetadata.timestampResolution = idb.options.timestampResolution;
            mTraceInterfaces.emplace_back(idb.options.name, idb.options.description,
                                          idb.options.filter, idb.options.os,
                                          idb.linkType);
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
        blockTotalLength = *reinterpret_cast<const uint32_t*>(&mReader.data()[
            mReader.mOffset + 4]);
    }

    switch (blockType) {
    case ENHANCED_PACKET_BLOCK: {
        EnhancedPacketBlock epb{};
        PcapNgBlockParser::readEPB(&mReader.data()[mReader.mOffset], epb);
        util::calculateTimestamps(mMetadata.timestampResolution, epb.timestampHigh,
                                  epb.timestampLow, &(packet.timestampSeconds),
                                  &(packet.timestampMicroseconds));
        packet.captureLength = epb.capturePacketLength;
        packet.length = epb.originalPacketLength;
        packet.data = epb.packetData;
        packet.interfaceIndex = epb.interfaceId;
        packet.dataLinkType = mTraceInterfaces[packet.interfaceIndex].dataLinkType;

        mReader.mOffset += epb.blockTotalLength;
        break;
    }
    case PACKET_BLOCK: {
        PacketBlock pb{};
        PcapNgBlockParser::readPB(&mReader.data()[mReader.mOffset], pb);
        util::calculateTimestamps(mMetadata.timestampResolution, pb.timestampHigh,
                                  pb.timestampLow, &(packet.timestampSeconds),
                                  &(packet.timestampMicroseconds));
        packet.captureLength = pb.capturePacketLength;
        packet.length = pb.originalPacketLength;
        packet.data = pb.packetData;
        packet.interfaceIndex = pb.interfaceId;
        packet.dataLinkType = mTraceInterfaces[packet.interfaceIndex].dataLinkType;

        mReader.mOffset += pb.blockTotalLength;
        break;
    }
    default: ;
    }

    return true;
}

template <typename TReader>
uint32_t PcapNgReader<TReader>::readBlock() {
    const auto blockType = *reinterpret_cast<const uint32_t*>(&mReader.data()[mReader.
        mOffset]);
    const auto blockTotalLength = *reinterpret_cast<const uint32_t*>(&mReader.data()[
        mReader.mOffset + 4]);

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
        mMetadata.timestampResolution = idb.options.timestampResolution;
        mTraceInterfaces.emplace_back(idb.options.name, idb.options.description,
                                      idb.options.filter, idb.options.os, idb.linkType);
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
        FPCAP_WARN("Parsing of Simple Packet Blocks not implemented, skipping\n");
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

} // namespace fpcap
