#include <mmpr/PcapNgBlockParser.h>

#include <mmpr/PcapNgBlockOptionParser.h>
#include "util.h"

namespace mmpr {
/**
 * 4.1.  Section Header Block
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                   Block Type = 0x0A0D0D0A                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |                      Byte-Order Magic                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |          Major Version        |         Minor Version         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 16 |                                                               |
 *    |                          Section Length                       |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 24 /                                                               /
 *    /                      Options (variable)                       /
 *    /                                                               /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void PcapNgBlockParser::readSHB(const uint8_t* data, SectionHeaderBlock& shb) {
    auto blockType = *(const uint32_t*)&data[0];
    MMPR_ASSERT(blockType == MMPR_SECTION_HEADER_BLOCK);

    shb.blockTotalLength = *(const uint32_t*)&data[4];

    auto byteOrderMagic = *(const uint32_t*)&data[8];
    MMPR_ASSERT(byteOrderMagic == 0x1A2B3C4D);

    shb.majorVersion = *(const uint16_t*)&data[12];
    shb.minorVersion = *(const uint16_t*)&data[14];

    // TODO: Also, special care should be taken in accessing this
    //      field: since the alignment of all the blocks in the file is
    //      32-bits, this field is not guaranteed to be aligned to a 64-bit
    //      boundary.  This could be a problem on 64-bit processors.
    shb.sectionLength = *(const int64_t*)&data[16];
    MMPR_ASSERT(shb.sectionLength != -1 ? shb.sectionLength % 4 == 0 : true);

    MMPR_DEBUG_LOG("--- [Section Header Block %p] ---\n", (void*)data);
    MMPR_DEBUG_LOG("[SHB] Block Total Length: %u\n", shb.blockTotalLength);
    MMPR_DEBUG_LOG("[SHB] Byte-Order Magic: 0x%08X\n", byteOrderMagic);
    MMPR_DEBUG_LOG_2("[SHB] Version: %u.%u\n", shb.majorVersion, shb.minorVersion);
    MMPR_DEBUG_LOG("[SHB] Section Length: %li\n", shb.sectionLength);

    // standard Section Header Block has size 28 (without any options)
    if (shb.blockTotalLength > 28) {
        uint32_t totalOptionsLength = shb.blockTotalLength - 28;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readSHBOption(data, option, 24 + readOptionsLength);
            readOptionsLength += option.totalLength();
            switch (option.type) {
            case MMPR_BLOCK_OPTION_COMMENT:
                shb.options.comment = std::string((char*)option.value, option.length);
                break;
            case MMPR_BLOCK_OPTION_SHB_OS:
                shb.options.os = std::string((char*)option.value, option.length);
                break;
            case MMPR_BLOCK_OPTION_SHB_HARDWARE:
                shb.options.hardware = std::string((char*)option.value, option.length);
                break;
            case MMPR_BLOCK_OPTION_SHB_USERAPPL:
                shb.options.userApplication =
                    std::string((char*)option.value, option.length);
                break;
            }
        }
    }

    // make sure that the block actually ends with block total length
    auto blockTotalLength = *(const uint32_t*)&data[shb.blockTotalLength - 4];
    MMPR_ASSERT(shb.blockTotalLength == blockTotalLength);
}

/**
 * 4.2.  Interface Description Block
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                    Block Type = 0x00000001                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |           LinkType            |           Reserved            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |                            SnapLen                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 16 /                                                               /
 *    /                      Options (variable)                       /
 *    /                                                               /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void PcapNgBlockParser::readIDB(const uint8_t* data, InterfaceDescriptionBlock& idb) {
    auto blockType = *(const uint32_t*)&data[0];
    MMPR_ASSERT(blockType == MMPR_INTERFACE_DESCRIPTION_BLOCK);

    idb.blockTotalLength = *(const uint32_t*)&data[4];
    idb.linkType = *(const uint16_t*)&data[8];
    idb.snapLen = *(const uint32_t*)&data[12];

    MMPR_DEBUG_LOG("--- [Interface Description Block %p] ---\n", (void*)data);
    MMPR_DEBUG_LOG("[IDB] Block Total Length: %u\n", idb.blockTotalLength);
    MMPR_DEBUG_LOG("[IDB] LinkType: 0x%04X\n", idb.linkType);
    MMPR_DEBUG_LOG("[IDB] SnapLen: %u\n", idb.snapLen);

    // standard Interface Description Block has size 20 (without any options)
    if (idb.blockTotalLength > 20) {
        uint32_t totalOptionsLength = idb.blockTotalLength - 20;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readIDBBlockOption(data, option,
                                                        16 + readOptionsLength);
            readOptionsLength += option.totalLength();
            switch (option.type) {
            case MMPR_BLOCK_OPTION_IDB_TSRESOL:
                MMPR_ASSERT(option.length == 1);
                idb.options.timestampResolution = util::fromIfTsresolUInt(*option.value);
                break;
            }
        }
    }

    // make sure that the block actually ends with block total length
    auto blockTotalLength = *(const uint32_t*)&data[idb.blockTotalLength - 4];
    MMPR_ASSERT(idb.blockTotalLength == blockTotalLength);
}

/**
 * 4.3.  Enhanced Packet Block
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                    Block Type = 0x00000006                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |                         Interface ID                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |                        Timestamp (High)                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 16 |                        Timestamp (Low)                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 20 |                    Captured Packet Length                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 24 |                    Original Packet Length                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 28 /                                                               /
 *    /                          Packet Data                          /
 *    /              variable length, padded to 32 bits               /
 *    /                                                               /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    /                                                               /
 *    /                      Options (variable)                       /
 *    /                                                               /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void PcapNgBlockParser::readEPB(const uint8_t* data, EnhancedPacketBlock& epb) {
    auto blockType = *(const uint32_t*)&data[0];
    MMPR_ASSERT(blockType == MMPR_ENHANCED_PACKET_BLOCK);

    epb.blockTotalLength = *(const uint32_t*)&data[4];
    epb.interfaceId = *(const uint32_t*)&data[8];
    epb.timestampHigh = *(const uint32_t*)&data[12];
    epb.timestampLow = *(const uint32_t*)&data[16];
    epb.capturePacketLength = *(const uint32_t*)&data[20];
    epb.originalPacketLength = *(const uint32_t*)&data[24];
    epb.packetData = &data[28];

    MMPR_DEBUG_LOG("--- [Enhanced Packet Block @%p] ---\n", (void*)data);
    MMPR_DEBUG_LOG("[EPB] Block Total Length: %u\n", epb.blockTotalLength);
    MMPR_DEBUG_LOG("[EPB] Interface ID: 0x%08X\n", epb.interfaceId);
    MMPR_DEBUG_LOG("[EPB] Timestamp (High): %u\n", epb.timestampHigh);
    MMPR_DEBUG_LOG("[EPB] Timestamp (Low): %u\n", epb.timestampLow);
    MMPR_DEBUG_LOG("[EPB] Captured Packet Length: %u\n", epb.capturePacketLength);
    MMPR_DEBUG_LOG("[EPB] Original Packet Length: %u\n", epb.originalPacketLength);
    MMPR_DEBUG_LOG("[EPB] Packet Data: %p\n", (void*)epb.packetData);

    // packet data is padded to 32 bits, calculate the total size in memory (including
    // padding)
    auto packetDataTotalLength =
        epb.capturePacketLength + (4 - epb.capturePacketLength % 4) % 4;
    // standard Enhanced Packet Block has size 32 (without packet data or options)
    if (epb.blockTotalLength - 32 > packetDataTotalLength) {
        uint32_t totalOptionsLength = epb.blockTotalLength - 32 - packetDataTotalLength;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readEPBOption(
                data, option, 32 + packetDataTotalLength + readOptionsLength);
            readOptionsLength += option.totalLength();
        }
    }

    // make sure that the block actually ends with block total length
    auto blockTotalLength = *(const uint32_t*)&data[epb.blockTotalLength - 4];
    MMPR_ASSERT(epb.blockTotalLength == blockTotalLength);
}

/**
 * 4.6.  Interface Statistics Block
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                   Block Type = 0x00000005                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |                         Interface ID                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |                        Timestamp (High)                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 16 |                        Timestamp (Low)                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 20 /                                                               /
 *    /                      Options (variable)                       /
 *    /                                                               /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void PcapNgBlockParser::readISB(const uint8_t* data, InterfaceStatisticsBlock& isb) {
    auto blockType = *(const uint32_t*)&data[0];
    MMPR_ASSERT(blockType == MMPR_INTERFACE_STATISTICS_BLOCK);

    isb.blockTotalLength = *(const uint32_t*)&data[4];
    isb.interfaceId = *(const uint32_t*)&data[8];
    isb.timestampHigh = *(const uint32_t*)&data[12];
    isb.timestampLow = *(const uint32_t*)&data[16];

    MMPR_DEBUG_LOG("--- [Interface Statistics Block @%p] ---\n", (void*)data);
    MMPR_DEBUG_LOG("[ISB] Block Type: 0x%08X\n", blockType);
    MMPR_DEBUG_LOG("[ISB] Block Total Length: %u\n", isb.blockTotalLength);
    MMPR_DEBUG_LOG("[ISB] Interface ID: 0x%08X\n", isb.interfaceId);
    MMPR_DEBUG_LOG("[ISB] Timestamp (High): %u\n", isb.timestampHigh);
    MMPR_DEBUG_LOG("[ISB] Timestamp (Low): %u\n", isb.timestampLow);

    // standard Interface Statistics Block has size 24 (without any options)
    if (isb.blockTotalLength > 20) {
        uint32_t totalOptionsLength = isb.blockTotalLength - 20;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readISBOption(data, option, 16 + readOptionsLength);
            readOptionsLength += option.totalLength();
        }
    }

    // make sure that the block actually ends with block total length
    auto blockTotalLength = *(const uint32_t*)&data[isb.blockTotalLength - 4];
    MMPR_ASSERT(isb.blockTotalLength == blockTotalLength);
}
} // namespace mmpr
