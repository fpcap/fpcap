#include "fpcap/pcapng/PcapNgBlockParser.hpp"

#include <fpcap/pcapng/PcapNgBlockOptionParser.hpp>
#include <fpcap/pcapng/PcapNgSectionHeaderBlock.hpp>
#include <fpcap/util.hpp>
#include <fpcap/pcapng/PcapNgBlockType.hpp>

namespace fpcap::pcapng {

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
    const auto blockType = *reinterpret_cast<const uint32_t*>(&data[0]);
    FPCAP_ASSERT(blockType == SECTION_HEADER_BLOCK);

    shb.blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[4]);

    const auto byteOrderMagic = *reinterpret_cast<const uint32_t*>(&data[8]);
    FPCAP_ASSERT(byteOrderMagic == 0x1A2B3C4D);

    shb.majorVersion = *reinterpret_cast<const uint16_t*>(&data[12]);
    shb.minorVersion = *reinterpret_cast<const uint16_t*>(&data[14]);

    // TODO: Also, special care should be taken in accessing this
    //      field: since the alignment of all the blocks in the file is
    //      32-bits, this field is not guaranteed to be aligned to a 64-bit
    //      boundary.  This could be a problem on 64-bit processors.
    shb.sectionLength = *reinterpret_cast<const int64_t*>(&data[16]);
    FPCAP_ASSERT(shb.sectionLength != -1 ? shb.sectionLength % 4 == 0 : true);

    FPCAP_DEBUG_LOG_1("--- [Section Header Block %p] ---\n",
                      reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[SHB] Block Total Length: %u\n", shb.blockTotalLength);
    FPCAP_DEBUG_LOG_1("[SHB] Byte-Order Magic: 0x%08X\n", byteOrderMagic);
    FPCAP_DEBUG_LOG_2("[SHB] Version: %u.%u\n", shb.majorVersion, shb.minorVersion);
    FPCAP_DEBUG_LOG_1("[SHB] Section Length: %li\n",
                      static_cast<long>(shb.sectionLength));

    // standard Section Header Block has size 28 (without any options)
    if (shb.blockTotalLength > 28) {
        const uint32_t totalOptionsLength = shb.blockTotalLength - 28;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readSHBOption(data, option, 24 + readOptionsLength);
            readOptionsLength += option.totalLength();
            switch (option.type) {
            case COMMENT:
                shb.options.comment = std::string(
                    reinterpret_cast<const char*>(option.value), option.length);
                break;
            case SHB_OS:
                shb.options.os = std::string(reinterpret_cast<const char*>(option.value),
                                             option.length);
                break;
            case SHB_HARDWARE:
                shb.options.hardware = std::string(
                    reinterpret_cast<const char*>(option.value), option.length);
                break;
            case SHB_USERAPPL:
                shb.options.userApplication =
                    std::string(reinterpret_cast<const char*>(option.value),
                                option.length);
                break;
            default: ;
            }
        }
    }

    // make sure that the block actually ends with block total length
    const auto blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[
        shb.blockTotalLength - 4]);
    FPCAP_ASSERT(shb.blockTotalLength == blockTotalLength);
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
void PcapNgBlockParser::readIDB(const uint8_t* data,
                                InterfaceDescriptionBlock& idb) {
    const auto blockType = *reinterpret_cast<const uint32_t*>(&data[0]);
    FPCAP_ASSERT(blockType == INTERFACE_DESCRIPTION_BLOCK);

    idb.blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[4]);
    idb.linkType = *reinterpret_cast<const uint16_t*>(&data[8]);
    idb.snapLen = *reinterpret_cast<const uint32_t*>(&data[12]);

    FPCAP_DEBUG_LOG_1("--- [Interface Description Block %p] ---\n",
                      reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[IDB] Block Total Length: %u\n", idb.blockTotalLength);
    FPCAP_DEBUG_LOG_1("[IDB] LinkType: 0x%04X\n", idb.linkType);
    FPCAP_DEBUG_LOG_1("[IDB] SnapLen: %u\n", idb.snapLen);

    // standard Interface Description Block has size 20 (without any options)
    if (idb.blockTotalLength > 20) {
        const uint32_t totalOptionsLength = idb.blockTotalLength - 20;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readIDBBlockOption(data, option,
                                                        16 + readOptionsLength);
            readOptionsLength += option.totalLength();
            switch (option.type) {
            case IDB_TSRESOL:
                FPCAP_ASSERT(option.length == 1);
                idb.options.timestampResolution = util::fromIfTsresolUInt(*option.value);
                break;
            case IDB_NAME:
                idb.options.name = PcapNgBlockOptionParser::parseUTF8(option);
                break;
            case IDB_DESCRIPTION:
                idb.options.description = PcapNgBlockOptionParser::parseUTF8(option);
                break;
            case IDB_FILTER:
                // skip first octet (filter code), interpret rest as string
                idb.options.filter = std::string(
                    reinterpret_cast<const char*>(&option.value[1]), option.length - 1u);
                break;
            case IDB_OS:
                idb.options.os = PcapNgBlockOptionParser::parseUTF8(option);
                break;
            default: ;
            }
        }
    }

    // make sure that the block actually ends with block total length
    const auto blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[
        idb.blockTotalLength - 4u]);
    FPCAP_ASSERT(idb.blockTotalLength == blockTotalLength);
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
    const auto blockType = *reinterpret_cast<const uint32_t*>(&data[0]);
    FPCAP_ASSERT(blockType == ENHANCED_PACKET_BLOCK);

    epb.blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[4]);
    epb.interfaceId = *reinterpret_cast<const uint32_t*>(&data[8]);
    epb.timestampHigh = *reinterpret_cast<const uint32_t*>(&data[12]);
    epb.timestampLow = *reinterpret_cast<const uint32_t*>(&data[16]);
    epb.capturePacketLength = *reinterpret_cast<const uint32_t*>(&data[20]);
    epb.originalPacketLength = *reinterpret_cast<const uint32_t*>(&data[24]);
    epb.packetData = &data[28];

    FPCAP_DEBUG_LOG_1("--- [Enhanced Packet Block @%p] ---\n",
                      reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[EPB] Block Total Length: %u\n", epb.blockTotalLength);
    FPCAP_DEBUG_LOG_1("[EPB] Interface ID: 0x%08X\n", epb.interfaceId);
    FPCAP_DEBUG_LOG_1("[EPB] Timestamp (High): %u\n", epb.timestampHigh);
    FPCAP_DEBUG_LOG_1("[EPB] Timestamp (Low): %u\n", epb.timestampLow);
    FPCAP_DEBUG_LOG_1("[EPB] Captured Packet Length: %u\n", epb.capturePacketLength);
    FPCAP_DEBUG_LOG_1("[EPB] Original Packet Length: %u\n", epb.originalPacketLength);
    FPCAP_DEBUG_LOG_1("[EPB] Packet Data: %p\n",
                      reinterpret_cast<const void*>(epb.packetData));

    // packet data is padded to 32 bits, calculate the total size in memory (including
    // padding)
    const auto packetDataTotalLength =
        epb.capturePacketLength + (4u - epb.capturePacketLength % 4u) % 4u;
    // standard Enhanced Packet Block has size 32 (without packet data or options)
    if (epb.blockTotalLength - 32u > packetDataTotalLength) {
        const uint32_t totalOptionsLength =
            epb.blockTotalLength - 32u - packetDataTotalLength;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readEPBOption(
                data, option, 32u + packetDataTotalLength + readOptionsLength);
            readOptionsLength += option.totalLength();
        }
    }

    // make sure that the block actually ends with block total length
    const auto blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[
        epb.blockTotalLength - 4u]);
    FPCAP_ASSERT(epb.blockTotalLength == blockTotalLength);
}

/**
 * Appendix A.  Packet Block (obsolete)
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                    Block Type = 0x00000006                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                      Block Total Length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |         Interface ID          |          Drops Count          |
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
void PcapNgBlockParser::readPB(const uint8_t* data, PacketBlock& pb) {
    const auto blockType = *reinterpret_cast<const uint32_t*>(&data[0]);
    FPCAP_ASSERT(blockType == PACKET_BLOCK);

    pb.blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[4]);
    pb.interfaceId = *reinterpret_cast<const uint16_t*>(&data[8]);
    pb.dropsCount = *reinterpret_cast<const uint16_t*>(&data[10]);
    pb.timestampHigh = *reinterpret_cast<const uint32_t*>(&data[12]);
    pb.timestampLow = *reinterpret_cast<const uint32_t*>(&data[16]);
    pb.capturePacketLength = *reinterpret_cast<const uint32_t*>(&data[20]);
    pb.originalPacketLength = *reinterpret_cast<const uint32_t*>(&data[24]);
    pb.packetData = &data[28];

    FPCAP_DEBUG_LOG_1("--- [Packet Block @%p] ---\n",
                      reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[PB] Block Total Length: %u\n", pb.blockTotalLength);
    FPCAP_DEBUG_LOG_1("[PB] Interface ID: 0x%04X\n", pb.interfaceId);
    FPCAP_DEBUG_LOG_1("[PB] Drops Count: 0x%04X\n", pb.dropsCount);
    FPCAP_DEBUG_LOG_1("[PB] Timestamp (High): %u\n", pb.timestampHigh);
    FPCAP_DEBUG_LOG_1("[PB] Timestamp (Low): %u\n", pb.timestampLow);
    FPCAP_DEBUG_LOG_1("[PB] Captured Packet Length: %u\n", pb.capturePacketLength);
    FPCAP_DEBUG_LOG_1("[PB] Original Packet Length: %u\n", pb.originalPacketLength);
    FPCAP_DEBUG_LOG_1("[PB] Packet Data: %p\n",
                      reinterpret_cast<const void*>(pb.packetData));

    // packet data is padded to 32 bits, calculate the total size in memory (including
    // padding)
    const auto packetDataTotalLength =
        pb.capturePacketLength + (4 - pb.capturePacketLength % 4) % 4;
    // standard Enhanced Packet Block has size 32 (without packet data or options)
    if (pb.blockTotalLength - 32 > packetDataTotalLength) {
        const uint32_t totalOptionsLength =
            pb.blockTotalLength - 32 - packetDataTotalLength;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readEPBOption(
                data, option, 32 + packetDataTotalLength + readOptionsLength);
            readOptionsLength += option.totalLength();
        }
    }

    // make sure that the block actually ends with block total length
    const auto blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[
        pb.blockTotalLength - 4]);
    FPCAP_ASSERT(pb.blockTotalLength == blockTotalLength);
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
void PcapNgBlockParser::readISB(const uint8_t* data,
                                InterfaceStatisticsBlock& isb) {
    const auto blockType = *reinterpret_cast<const uint32_t*>(&data[0]);
    FPCAP_ASSERT(blockType == INTERFACE_STATISTICS_BLOCK);

    isb.blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[4]);
    isb.interfaceId = *reinterpret_cast<const uint32_t*>(&data[8]);
    isb.timestampHigh = *reinterpret_cast<const uint32_t*>(&data[12]);
    isb.timestampLow = *reinterpret_cast<const uint32_t*>(&data[16]);

    FPCAP_DEBUG_LOG_1("--- [Interface Statistics Block @%p] ---\n",
                      reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[ISB] Block Type: 0x%08X\n", blockType);
    FPCAP_DEBUG_LOG_1("[ISB] Block Total Length: %u\n", isb.blockTotalLength);
    FPCAP_DEBUG_LOG_1("[ISB] Interface ID: 0x%08X\n", isb.interfaceId);
    FPCAP_DEBUG_LOG_1("[ISB] Timestamp (High): %u\n", isb.timestampHigh);
    FPCAP_DEBUG_LOG_1("[ISB] Timestamp (Low): %u\n", isb.timestampLow);

    // standard Interface Statistics Block has size 24 (without any options)
    if (isb.blockTotalLength > 20) {
        const uint32_t totalOptionsLength = isb.blockTotalLength - 20;
        uint32_t readOptionsLength = 0;
        while (readOptionsLength < totalOptionsLength) {
            Option option{};
            PcapNgBlockOptionParser::readISBOption(data, option, 16 + readOptionsLength);
            readOptionsLength += option.totalLength();
        }
    }

    // make sure that the block actually ends with block total length
    const auto blockTotalLength = *reinterpret_cast<const uint32_t*>(&data[
        isb.blockTotalLength - 4]);
    FPCAP_ASSERT(isb.blockTotalLength == blockTotalLength);
}

} // namespace fpcap
