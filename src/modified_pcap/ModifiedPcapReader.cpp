#include "mmpr/modified_pcap/ModifiedPcapReader.hpp"
#include <iostream>

namespace mmpr {

template <typename TReader>
ModifiedPcapReader<TReader>::ModifiedPcapReader(const std::string& filepath)
    : mReader(filepath) {
    modified_pcap::FileHeader fileHeader{};
    ModifiedPcapParser::readFileHeader(mReader.data(), fileHeader);
    mReader.mOffset += 24;
    mLinkType = fileHeader.linkType;
}

template <typename TReader>
ModifiedPcapReader<TReader>::ModifiedPcapReader(TReader&& reader)
    : mReader(std::forward<TReader>(reader)) {
    modified_pcap::FileHeader fileHeader{};
    ModifiedPcapParser::readFileHeader(mReader.data(), fileHeader);
    mReader.mOffset += 24;
    mLinkType = fileHeader.linkType;
}

template <typename TReader>
bool ModifiedPcapReader<TReader>::isExhausted() const {
    return mReader.isExhausted();
}

template <typename TReader>
bool ModifiedPcapReader<TReader>::readNextPacket(Packet& packet) {
    if (isExhausted()) {
        // nothing more to read
        return false;
    }

    // make sure there are enough bytes to read
    if (mReader.getSafeToReadSize() < 24) {
        std::cerr << "Error: Expected to read at least one more raw packet record (24 "
                     "bytes at least), but there are only "
                  << mReader.getSafeToReadSize() << " bytes left in the file"
                  << std::endl;
        return false;
    }

    modified_pcap::PacketRecord packetRecord{};
    ModifiedPcapParser::readPacketRecord(&mReader.data()[mReader.mOffset], packetRecord);
    packet.timestampSeconds = packetRecord.timestampSeconds;
    packet.captureLength = packetRecord.captureLength;
    packet.length = packetRecord.length;
    packet.data = packetRecord.data;
    packet.dataLinkType = mLinkType;

    mReader.mOffset += 24 + packetRecord.captureLength;

    return true;
}

template class ModifiedPcapReader<FReadFileReader>;
template class ModifiedPcapReader<MMapFileReader>;
template class ModifiedPcapReader<ZstdFileReader>;

} // namespace mmpr
