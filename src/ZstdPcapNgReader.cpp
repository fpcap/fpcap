#include <mmpr/ZstdPcapNgReader.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <mmpr/PcapNgBlockParser.h>
#include <mmpr/ZstdDecompressor.h>
#include <stdexcept>
#include <sys/mman.h>

using namespace std;
using namespace boost::filesystem;
using namespace boost::algorithm;

namespace mmpr {
ZstdPcapNgReader::ZstdPcapNgReader(const std::string& filepath) : PcapNgReader(filepath) {
    // TODO determine by file header or similar
    if (!ends_with(filepath, ".zst") && !ends_with(filepath, ".zstd")) {
        throw runtime_error(
            "ZstdPcapNgReader only supports files with .zst or .zstd endings");
    }
}

void ZstdPcapNgReader::open() {
    mData = reinterpret_cast<const uint8_t*>(
        ZstdDecompressor::decompressFileInMemory(mFilepath, mFileSize));
    assert(mFileSize > 0);
}

bool ZstdPcapNgReader::isExhausted() const {
    return mOffset >= mFileSize;
}

bool ZstdPcapNgReader::readNextPacket(Packet& packet) {
    if (isExhausted()) {
        // nothing more to read
        return false;
    }

    // make sure there are enough bytes to read
    if (mFileSize - mOffset < 8) {
        throw runtime_error("Expected to read at least one more block (8 bytes at "
                            "least), but there are only " +
                            to_string(mFileSize - mOffset) + " bytes left in the file");
    }

    uint32_t blockType = *(uint32_t*)&mData[mOffset];
    uint32_t blockTotalLength = *(uint32_t*)&mData[mOffset + 4];

    // TODO add support for Simple Packet Blocks
    while (blockType != MMPR_ENHANCED_PACKET_BLOCK) {
        if (blockType == MMPR_SECTION_HEADER_BLOCK) {
            SectionHeaderBlock shb{};
            PcapNgBlockParser::readSHB(&mData[mOffset], shb);
            mMetadata.comment = shb.options.comment;
            mMetadata.os = shb.options.os;
            mMetadata.hardware = shb.options.hardware;
            mMetadata.userApplication = shb.options.userApplication;
        } else if (blockType == MMPR_INTERFACE_DESCRIPTION_BLOCK) {
            InterfaceDescriptionBlock idb{};
            PcapNgBlockParser::readIDB(&mData[mOffset], idb);
            mDataLinkType = idb.linkType;
            mMetadata.timestampResolution = idb.options.timestampResolution;
        }

        mOffset += blockTotalLength;

        if (isExhausted()) {
            // we have reached the end of the file
            return false;
        }

        // make sure there are enough bytes to read
        if (mFileSize - mOffset < 8) {
            throw runtime_error("Expected to read at least one more block (8 bytes at "
                                "least), but there are only " +
                                to_string(mFileSize - mOffset) +
                                " bytes left in the file");
        }

        // try to read next block type
        blockType = *(const uint32_t*)&mData[mOffset];
        blockTotalLength = *(const uint32_t*)&mData[mOffset + 4];
    }

    EnhancedPacketBlock epb{};
    PcapNgBlockParser::readEPB(&mData[mOffset], epb);
    packet.timestampLow = epb.timestampLow;
    packet.timestampHigh = epb.timestampHigh;
    packet.captureLength = epb.capturePacketLength;
    packet.length = epb.originalPacketLength;
    packet.data = epb.packetData;

    mOffset += epb.blockTotalLength;

    return true;
}

void ZstdPcapNgReader::close() {
    free((void*)mData);
}

/**
 * 3.1.  General Block Structure
 *
 *                        1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 0 |                          Block Type                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 4 |                      Block Total Length                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 8 /                          Block Body                           /
 *   /              variable length, padded to 32 bits               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Block Total Length                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
uint32_t ZstdPcapNgReader::readBlock() {
    const auto blockType = *(const uint32_t*)&mData[mOffset];
    const auto blockTotalLength = *(const uint32_t*)&mData[mOffset + 4];

    switch (blockType) {
    case MMPR_SECTION_HEADER_BLOCK: {
        SectionHeaderBlock shb{};
        PcapNgBlockParser::readSHB(&mData[mOffset], shb);
        mMetadata.comment = shb.options.comment;
        mMetadata.os = shb.options.os;
        mMetadata.hardware = shb.options.hardware;
        mMetadata.userApplication = shb.options.userApplication;
        break;
    }
    case MMPR_INTERFACE_DESCRIPTION_BLOCK: {
        InterfaceDescriptionBlock idb{};
        PcapNgBlockParser::readIDB(&mData[mOffset], idb);
        mDataLinkType = idb.linkType;
        mMetadata.timestampResolution = idb.options.timestampResolution;
        break;
    }
    case MMPR_ENHANCED_PACKET_BLOCK: {
        EnhancedPacketBlock epb{};
        PcapNgBlockParser::readEPB(&mData[mOffset], epb);
        break;
    }
    case MMPR_SIMPLE_PACKET_BLOCK: {
        MMPR_WARN("Parsing of Simple Packet Blocks not implemented, skipping\n");
        break;
    }
    case MMPR_NAME_RESOLUTION_BLOCK: {
        MMPR_WARN("Parsing of Name Resolution Blocks not implemented, skipping\n");
        break;
    }
    case MMPR_INTERFACE_STATISTICS_BLOCK: {
        InterfaceStatisticsBlock isb{};
        PcapNgBlockParser::readISB(&mData[mOffset], isb);
        break;
    }
    case MMPR_DECRYPTION_SECRETS_BLOCK: {
        MMPR_WARN("Parsing of Decryption Secrets Blocks not implemented, skipping\n");
        break;
    }
    case MMPR_CUSTOM_CAN_COPY_BLOCK: {
        MMPR_WARN("Parsing of Custom (Can Copy) Blocks not implemented, skipping\n");
        break;
    }
    case MMPR_CUSTOM_DO_NOT_COPY_BLOCK: {
        MMPR_WARN("Parsing of Custom (Do Not Copy) Blocks not implemented, skipping\n");
        break;
    }
    default: {
        MMPR_WARN_1("Encountered unknown block type: %u, skipping", blockType);
        break;
    }
    }

    // skip to next block
    mOffset += (size_t)blockTotalLength;

    return blockType;
}

} // namespace mmpr
