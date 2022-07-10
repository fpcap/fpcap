#include "mmpr/modified_pcap/MMModifiedPcapReader.h"

#include "mmpr/modified_pcap/ModifiedPcapParser.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

using namespace std;

namespace mmpr {
MMModifiedPcapReader::MMModifiedPcapReader(const string& filepath)
    : ModifiedPcapReader(filepath) {}

void MMModifiedPcapReader::open() {
    mFileDescriptor = ::open(mFilepath.c_str(), O_RDONLY, 0);
    if (mFileDescriptor < 0) {
        throw runtime_error("Error while reading file " +
                            std::filesystem::absolute(mFilepath).string() + ": " +
                            strerror(errno));
    }

    mFileSize = lseek(mFileDescriptor, 0, SEEK_END);
    mMappedSize = (mFileSize / MMPR_PAGE_SIZE + 1) * MMPR_PAGE_SIZE;

    auto mmapResult =
        mmap(nullptr, mMappedSize, PROT_READ, MAP_SHARED, mFileDescriptor, 0);
    if (mmapResult == MAP_FAILED) {
        ::close(mFileDescriptor);
        throw runtime_error("Error while mapping file " +
                            std::filesystem::absolute(mFilepath).string() + ": " +
                            strerror(errno));
    }

    mOffset = 0;
    mMappedMemory = reinterpret_cast<const uint8_t*>(mmapResult);

    ModifiedPcapFileHeader fileHeader{};
    ModifiedPcapParser::readFileHeader(mMappedMemory, fileHeader);
    mOffset += 24;
}

bool MMModifiedPcapReader::isExhausted() const {
    return mOffset >= mFileSize;
}

bool MMModifiedPcapReader::readNextPacket(Packet& packet) {
    if (isExhausted()) {
        // nothing more to read
        return false;
    }

    // make sure there are enough bytes to read
    if (mFileSize - mOffset < 24) {
        throw runtime_error(
            "Expected to read at least one more raw packet record (24 bytes "
            "at least), but there are only " +
            to_string(mFileSize - mOffset) + " bytes left in the file");
    }

    ModifiedPcapPacketRecord packetRecord{};
    ModifiedPcapParser::readPacketRecord(&mMappedMemory[mOffset], packetRecord);
    packet.timestampSeconds = packetRecord.timestampSeconds;
    packet.captureLength = packetRecord.captureLength;
    packet.length = packetRecord.length;
    packet.data = packetRecord.data;

    mOffset += 24 + packetRecord.captureLength;

    return true;
}

void MMModifiedPcapReader::close() {
    munmap((void*)mMappedMemory, mMappedSize);
    ::close(mFileDescriptor);
}

} // namespace mmpr
