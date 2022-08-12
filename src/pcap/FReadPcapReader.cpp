#include "mmpr/pcap/FReadPcapReader.h"

#include "mmpr/pcap/PcapParser.h"
#include "util.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <stdexcept>

using namespace std;

namespace mmpr {
FReadPcapReader::FReadPcapReader(const string& filepath) : PcapReader(filepath) {
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
}

void FReadPcapReader::open() {
    mFileSize = std::filesystem::file_size(mFilepath);
    auto data = new char[mFileSize];
    FILE* const inFile = fopen(mFilepath.c_str(), "rb");
    if (fread(data, 1, mFileSize, inFile) != mFileSize) {
        throw runtime_error("fread error: " + std::string(strerror(errno)));
    }
    fclose(inFile);

    mMappedMemory = reinterpret_cast<uint8_t*>(data);
    mOffset = 0;

    FileHeader fileHeader{};
    PcapParser::readFileHeader(mMappedMemory, fileHeader);
    mDataLinkType = fileHeader.linkType;
    mTimestampFormat = fileHeader.timestampFormat;
    mOffset += 24;
}

bool FReadPcapReader::isExhausted() const {
    return mOffset >= mFileSize;
}

bool FReadPcapReader::readNextPacket(Packet& packet) {
    if (isExhausted()) {
        // nothing more to read
        return false;
    }

    // make sure there are enough bytes to read
    if (mFileSize - mOffset < 16) {
        throw runtime_error("Expected to read at least one more packet record (16 bytes "
                            "at least), but there are only " +
                            to_string(mFileSize - mOffset) + " bytes left in the file");
    }

    PacketRecord packetRecord{};
    PcapParser::readPacketRecord(&mMappedMemory[mOffset], packetRecord);
    packet.timestampSeconds = packetRecord.timestampSeconds;
    packet.timestampMicroseconds = mTimestampFormat == FileHeader::MICROSECONDS
                                       ? packetRecord.timestampSubSeconds
                                       : packetRecord.timestampSubSeconds / 1000;
    packet.captureLength = packetRecord.captureLength;
    packet.length = packetRecord.length;
    packet.data = packetRecord.data;

    mOffset += 16 + packetRecord.captureLength;

    return true;
}

void FReadPcapReader::close() {
    delete[] mMappedMemory;
}

} // namespace mmpr
