#include <mmpr/pcap/MMPcapReader.h>

#include "util.h"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <mmpr/pcap/PcapParser.h>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

using namespace std;
using namespace boost::filesystem;
using namespace boost::algorithm;

namespace mmpr {
MMPcapReader::MMPcapReader(const string& filepath) : PcapReader(filepath) {
    // TODO determine by file header or similar
    if (!ends_with(filepath, ".pcap") && !ends_with(filepath, ".cap")) {
        throw runtime_error(
            "MMPcapReader only supports files with .pcap or .cap endings");
    }
}

void MMPcapReader::open() {
    mFileDescriptor = ::open(mFilepath.c_str(), O_RDONLY, 0);
    if (mFileDescriptor < 0) {
        throw runtime_error("Error while reading file " + absolute(mFilepath).string() +
                            ": " + strerror(errno));
    }

    mFileSize = lseek(mFileDescriptor, 0, SEEK_END);
    mMappedSize = (mFileSize / MMPR_PAGE_SIZE + 1) * MMPR_PAGE_SIZE;

    auto mmapResult =
        mmap(nullptr, mMappedSize, PROT_READ, MAP_SHARED, mFileDescriptor, 0);
    if (mmapResult == MAP_FAILED) {
        ::close(mFileDescriptor);
        throw runtime_error("Error while mapping file " + absolute(mFilepath).string() +
                            ": " + strerror(errno));
    }

    mOffset = 0;
    mMappedMemory = reinterpret_cast<const uint8_t*>(mmapResult);

    FileHeader fileHeader{};
    PcapParser::readFileHeader(mMappedMemory, fileHeader);
    mDataLinkType = fileHeader.linkType;
    mTimestampFormat = fileHeader.timestampFormat;
    mOffset += 24;
}

bool MMPcapReader::isExhausted() const {
    return mOffset >= mFileSize;
}

bool MMPcapReader::readNextPacket(Packet& packet) {
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

void MMPcapReader::close() {
    munmap((void*)mMappedMemory, mMappedSize);
    ::close(mFileDescriptor);
}

} // namespace mmpr
