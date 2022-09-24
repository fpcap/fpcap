#include "mmpr/pcap/FReadPcapReader.h"

#include "mmpr/pcap/PcapParser.h"
#include "mmpr/util.h"
#include <algorithm>
#include <stdexcept>

using namespace std;

namespace mmpr {

FReadPcapReader::FReadPcapReader(const string& filepath)
    : PcapReader(filepath), mReader(filepath) {
    uint32_t magicNumber = util::read32bitsFromFile(filepath);
    if (magicNumber != MMPR_MAGIC_NUMBER_PCAP_MICROSECONDS &&
        magicNumber != MMPR_MAGIC_NUMBER_PCAP_NANOSECONDS) {
        stringstream sstream;
        sstream << std::hex << magicNumber;
        string hex = sstream.str();
        std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
        throw std::runtime_error("Expected PCAP format to start with appropriate magic "
                                 "numbers, instead got: 0x" +
                                 hex + ", possibly little/big endian issue");
    }

    FileHeader fileHeader{};
    PcapParser::readFileHeader(mReader.mData, fileHeader);
    mDataLinkType = fileHeader.linkType;
    mTimestampFormat = fileHeader.timestampFormat;
    mReader.mOffset += 24;
}

bool FReadPcapReader::readNextPacket(Packet& packet) {
    if (isExhausted()) {
        // nothing more to read
        return false;
    }

    // make sure there are enough bytes to read
    if (mReader.getSafeToReadSize() < 16) {
        throw runtime_error("Expected to read at least one more packet record (16 bytes "
                            "at least), but there are only " +
                            to_string(mReader.getSafeToReadSize()) +
                            " bytes left in the file");
    }

    PacketRecord packetRecord{};
    PcapParser::readPacketRecord(&mReader.mData[mReader.mOffset], packetRecord);
    packet.timestampSeconds = packetRecord.timestampSeconds;
    packet.timestampMicroseconds = mTimestampFormat == FileHeader::MICROSECONDS
                                       ? packetRecord.timestampSubSeconds
                                       : packetRecord.timestampSubSeconds / 1000;
    packet.captureLength = packetRecord.captureLength;
    packet.length = packetRecord.length;
    packet.data = packetRecord.data;

    mReader.mOffset += 16 + packetRecord.captureLength;

    return true;
}

} // namespace mmpr
