#include "mmpr/pcap/PcapReader.hpp"
#include <iostream>

namespace mmpr {

template <typename TReader>
PcapReader<TReader>::PcapReader(const std::string& filepath) : mReader(filepath) {
    pcap::FileHeader fileHeader{};
    PcapParser::readFileHeader(mReader.data(), fileHeader);
    mDataLinkType = fileHeader.dataLinkType;
    mTimestampFormat = fileHeader.timestampFormat;
    mReader.mOffset += 24;
}

template <typename TReader>
PcapReader<TReader>::PcapReader(TReader&& reader)
    : mReader(std::forward<TReader>(reader)) {
    pcap::FileHeader fileHeader{};
    PcapParser::readFileHeader(mReader.data(), fileHeader);
    mDataLinkType = fileHeader.dataLinkType;
    mTimestampFormat = fileHeader.timestampFormat;
    mReader.mOffset += 24;
}

template <typename TReader>
bool PcapReader<TReader>::isExhausted() const {
    return mReader.isExhausted();
}

template <typename TReader>
bool PcapReader<TReader>::readNextPacket(Packet& packet) {
    if (isExhausted()) {
        // nothing more to read
        return false;
    }

    // make sure there are enough bytes to read
    if (mReader.getSafeToReadSize() < 16) {
        std::cerr << "Error: Expected to read at least one more packet record (16 bytes "
                     "at least), but there are only "
                  << mReader.getSafeToReadSize() << " bytes left in the file"
                  << std::endl;
        return false;
    }

    pcap::PacketRecord packetRecord{};
    PcapParser::readPacketRecord(&mReader.data()[mReader.mOffset], packetRecord);
    mReader.mOffset += 16;

    if (packetRecord.captureLength > (mReader.mFileSize - mReader.mOffset)) {
        std::cerr << "Error: capture file appears to be cut short, trying to read "
                  << packetRecord.captureLength << " bytes, but only "
                  << (mReader.mFileSize - mReader.mOffset) << " are available" << std::endl;
        mReader.mOffset = mReader.mFileSize;
        return false;
    }

    packet.timestampSeconds = packetRecord.timestampSeconds;
    packet.timestampMicroseconds = mTimestampFormat == pcap::FileHeader::MICROSECONDS
                                       ? packetRecord.timestampSubSeconds
                                       : packetRecord.timestampSubSeconds / 1000;
    packet.captureLength = packetRecord.captureLength;
    packet.length = packetRecord.length;
    packet.data = packetRecord.data;
    packet.dataLinkType = mDataLinkType;

    mReader.mOffset += packetRecord.captureLength;

    return true;
}

template class PcapReader<FReadFileReader>;
template class PcapReader<MMapFileReader>;
template class PcapReader<ZstdFileReader>;

} // namespace mmpr
