#include "mmpr/pcap/StreamPcapReader.h"

#include "mmpr/pcap/StreamPcapParser.h"
#include "util.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#include <unistd.h>

using namespace std;

namespace mmpr {
StreamPcapReader::StreamPcapReader(const string& filepath) : PcapReader(filepath) {
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

void StreamPcapReader::open() {
    int fd = ::open(mFilepath.c_str(), O_RDONLY, 0);
    if (fd < 0) {
        throw runtime_error("Error while reading file " +
                            std::filesystem::absolute(mFilepath).string() + ": " +
                            strerror(errno));
    }
    mFileSize = lseek(fd, 0, SEEK_END);
    ::close(fd);

    mStream = std::ifstream(mFilepath, std::ios::binary);
    mOffset = 0;

    FileHeader fileHeader{};
    StreamPcapParser::readFileHeader(mStream, fileHeader);
    mDataLinkType = fileHeader.linkType;
    mTimestampFormat = fileHeader.timestampFormat;
    mOffset += 24;
}

bool StreamPcapReader::isExhausted() const {
    return mOffset >= mFileSize;
}

bool StreamPcapReader::readNextPacket(Packet& packet) {
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
    StreamPcapParser::readPacketRecord(mStream, packetRecord);
    Packet result;
    result.timestampSeconds = packetRecord.timestampSeconds;
    result.timestampMicroseconds = mTimestampFormat == FileHeader::MICROSECONDS
                                       ? packetRecord.timestampSubSeconds
                                       : packetRecord.timestampSubSeconds / 1000;
    result.captureLength = packetRecord.captureLength;
    result.length = packetRecord.length;
    result.data = packetRecord.data;
    result.dataDynamicallyAllocated = packetRecord.dataDynamicallyAllocated;

    packet.swap(result);

    mOffset += 16 + packetRecord.captureLength;

    return true;
}

void StreamPcapReader::close() {
    if (mStream.is_open()) {
        mStream.close();
    }
}

} // namespace mmpr
