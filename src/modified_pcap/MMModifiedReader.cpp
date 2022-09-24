#include "mmpr/modified_pcap/MMModifiedPcapReader.h"

#include "mmpr/modified_pcap/ModifiedPcapParser.h"
#include <stdexcept>

using namespace std;

namespace mmpr {

MMModifiedPcapReader::MMModifiedPcapReader(const string& filepath)
    : ModifiedPcapReader(filepath), mReader(filepath) {
    ModifiedPcapFileHeader fileHeader{};
    int magicNumber =
        ModifiedPcapParser::readFileHeader(mReader.data(), fileHeader);
    if (magicNumber == MMPR_MAGIC_NUMBER_MODIFIED_PCAP_BE) {
        throw runtime_error("Modified PCAP format in Big Endian is not supported yet");
    }
    mReader.mOffset += 24;
}

bool MMModifiedPcapReader::readNextPacket(Packet& packet) {
    if (isExhausted()) {
        // nothing more to read
        return false;
    }

    // make sure there are enough bytes to read
    if (mReader.getSafeToReadSize() < 24) {
        throw runtime_error(
            "Expected to read at least one more raw packet record (24 bytes "
            "at least), but there are only " +
            to_string(mReader.getSafeToReadSize()) + " bytes left in the file");
    }

    ModifiedPcapPacketRecord packetRecord{};
    ModifiedPcapParser::readPacketRecord(&mReader.data()[mReader.mOffset],
                                         packetRecord);
    packet.timestampSeconds = packetRecord.timestampSeconds;
    packet.captureLength = packetRecord.captureLength;
    packet.length = packetRecord.length;
    packet.data = packetRecord.data;

    mReader.mOffset += 24 + packetRecord.captureLength;

    return true;
}

} // namespace mmpr
