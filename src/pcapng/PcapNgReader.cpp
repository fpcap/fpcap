#include "fpcap/pcapng/PcapNgReader.hpp"

#include <iostream>
#include <sstream>

namespace fpcap {

template <typename TReader>
PcapNgReader<TReader>::PcapNgReader(const std::string& filepath) : mReader(filepath) {
    uint32_t magicNumber = *(uint32_t*)mReader.data();
    if (magicNumber != PCAPNG) {
        std::stringstream sstream;
        sstream << std::hex << magicNumber;
        std::string hex = sstream.str();
        throw std::runtime_error(
            "Expected PcapNG format to start with appropriate magic "
            "number, instead got: 0x" +
            hex + ", possibly little/big endian issue while reading file " + filepath);
    }
}

template <typename TReader>
PcapNgReader<TReader>::PcapNgReader(TReader&& reader)
    : mReader(std::forward<TReader>(reader)) {
    uint32_t magicNumber = *(uint32_t*)mReader.data();
    if (magicNumber != PCAPNG) {
        std::stringstream sstream;
        sstream << std::hex << magicNumber;
        std::string hex = sstream.str();
        throw std::runtime_error(
            "Expected PcapNG format to start with appropriate magic "
            "number, instead got: 0x" +
            hex + ", possibly little/big endian issue while reading file " +
            getFilepath());
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

    uint32_t blockType = *(uint32_t*)&mReader.data()[mReader.mOffset];
    uint32_t blockTotalLength = *(uint32_t*)&mReader.data()[mReader.mOffset + 4];

    // TODO add support for Simple Packet Blocks
    while (blockType != FPCAP_ENHANCED_PACKET_BLOCK && blockType != FPCAP_PACKET_BLOCK) {
        if (blockType == FPCAP_SECTION_HEADER_BLOCK) {
            pcapng::SectionHeaderBlock shb{};
            PcapNgBlockParser::readSHB(&mReader.data()[mReader.mOffset], shb);
            mMetadata.comment = shb.options.comment;
            mMetadata.os = shb.options.os;
            mMetadata.hardware = shb.options.hardware;
            mMetadata.userApplication = shb.options.userApplication;
        } else if (blockType == FPCAP_INTERFACE_DESCRIPTION_BLOCK) {
            pcapng::InterfaceDescriptionBlock idb{};
            PcapNgBlockParser::readIDB(&mReader.data()[mReader.mOffset], idb);
            mMetadata.timestampResolution = idb.options.timestampResolution;
            mTraceInterfaces.emplace_back(idb.options.name, idb.options.description,
                                          idb.options.filter, idb.options.os, idb.linkType);
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
        blockType = *(const uint32_t*)&mReader.data()[mReader.mOffset];
        blockTotalLength = *(const uint32_t*)&mReader.data()[mReader.mOffset + 4];
    }

    switch (blockType) {
    case FPCAP_ENHANCED_PACKET_BLOCK: {
        pcapng::EnhancedPacketBlock epb{};
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
    case FPCAP_PACKET_BLOCK: {
        pcapng::PacketBlock pb{};
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
    }

    return true;
}

template <typename TReader>
uint32_t PcapNgReader<TReader>::readBlock() {
    const auto blockType = *(const uint32_t*)&mReader.data()[mReader.mOffset];
    const auto blockTotalLength = *(const uint32_t*)&mReader.data()[mReader.mOffset + 4];

    switch (blockType) {
    case FPCAP_SECTION_HEADER_BLOCK: {
        pcapng::SectionHeaderBlock shb{};
        PcapNgBlockParser::readSHB(&mReader.data()[mReader.mOffset], shb);
        mMetadata.comment = shb.options.comment;
        mMetadata.os = shb.options.os;
        mMetadata.hardware = shb.options.hardware;
        mMetadata.userApplication = shb.options.userApplication;
        break;
    }
    case FPCAP_INTERFACE_DESCRIPTION_BLOCK: {
        pcapng::InterfaceDescriptionBlock idb{};
        PcapNgBlockParser::readIDB(&mReader.data()[mReader.mOffset], idb);
        mMetadata.timestampResolution = idb.options.timestampResolution;
        mTraceInterfaces.emplace_back(idb.options.name, idb.options.description,
                                      idb.options.filter, idb.options.os, idb.linkType);
        break;
    }
    case FPCAP_ENHANCED_PACKET_BLOCK: {
        pcapng::EnhancedPacketBlock epb{};
        PcapNgBlockParser::readEPB(&mReader.data()[mReader.mOffset], epb);
        break;
    }
    case FPCAP_PACKET_BLOCK: {
        // deprecated in newer versions of PcapNG
        pcapng::PacketBlock pb{};
        PcapNgBlockParser::readPB(&mReader.data()[mReader.mOffset], pb);
        break;
    }
    case FPCAP_SIMPLE_PACKET_BLOCK: {
        FPCAP_WARN("Parsing of Simple Packet Blocks not implemented, skipping\n");
        break;
    }
    case FPCAP_NAME_RESOLUTION_BLOCK: {
        FPCAP_WARN("Parsing of Name Resolution Blocks not implemented, skipping\n");
        break;
    }
    case FPCAP_INTERFACE_STATISTICS_BLOCK: {
        pcapng::InterfaceStatisticsBlock isb{};
        PcapNgBlockParser::readISB(&mReader.data()[mReader.mOffset], isb);
        break;
    }
    case FPCAP_DECRYPTION_SECRETS_BLOCK: {
        FPCAP_WARN("Parsing of Decryption Secrets Blocks not implemented, skipping\n");
        break;
    }
    case FPCAP_CUSTOM_CAN_COPY_BLOCK: {
        FPCAP_WARN("Parsing of Custom (Can Copy) Blocks not implemented, skipping\n");
        break;
    }
    case FPCAP_CUSTOM_DO_NOT_COPY_BLOCK: {
        FPCAP_WARN("Parsing of Custom (Do Not Copy) Blocks not implemented, skipping\n");
        break;
    }
    default: {
        FPCAP_WARN_1("Encountered unknown block type: %u, skipping\n", blockType);
        break;
    }
    }

    // skip to next block
    mReader.mOffset += (size_t)blockTotalLength;

    return blockType;
}

template <typename TReader>
TraceInterface PcapNgReader<TReader>::getTraceInterface(size_t id) const {
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
