#ifndef MMPR_PCAPPARSER_H
#define MMPR_PCAPPARSER_H

#include <mmpr/mmpr.h>

namespace mmpr {
class PcapParser {
public:
    /**
     *
     *                         1                   2                   3
     *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  0 |                          Magic Number                         |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  4 |          Major Version        |         Minor Version         |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  8 |                           Reserved1                           |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 12 |                           Reserved2                           |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 16 |                            SnapLen                            |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 20 | FCS |f|0 0 0 0 0 0 0 0 0 0 0 0|         LinkType              |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */
    static void readFileHeader(const uint8_t* data, FileHeader& fh) {
        auto magicNumber = *(const uint32_t*)&data[0];
        MMPR_ASSERT(magicNumber == 0xA1B2C3D4 || magicNumber == 0xA1B23C4D);

        if (magicNumber == 0xA1B2C3D4) {
            fh.timestampFormat = FileHeader::MICROSECONDS;
        } else {
            fh.timestampFormat = FileHeader::NANOSECONDS;
        }

        fh.majorVersion = *(const uint16_t*)&data[4];
        fh.minorVersion = *(const uint16_t*)&data[6];

        fh.snapLength = *(const uint32_t*)&data[16];
        fh.fcsSequence = *(const uint16_t*)&data[20];
        fh.linkType = *(const uint16_t*)&data[22];

        MMPR_DEBUG_LOG("--- [File Header %p] ---\n", (void*)data);
        MMPR_DEBUG_LOG("[FH] Timestamp Format: %s\n",
                       fh.timestampFormat == FileHeader::MICROSECONDS ? "MICROSECONDS"
                                                                      : "NANOSECONDS");
        MMPR_DEBUG_LOG_2("[FH] Version: %u.%u\n", fh.majorVersion, fh.minorVersion);
        MMPR_DEBUG_LOG("[FH] Snap Length: %u\n", fh.snapLength);
        MMPR_DEBUG_LOG("[FH] Link Type: %u\n", fh.linkType);
    }

    /**
     *                         1                   2                   3
     *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  0 |                      Timestamp (Seconds)                      |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  4 |            Timestamp (Microseconds or nanoseconds)            |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  8 |                    Captured Packet Length                     |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 12 |                    Original Packet Length                     |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 16 /                                                               /
     *    /                          Packet Data                          /
     *    /                        variable length                        /
     *    /                                                               /
     *    +---------------------------------------------------------------+
     */
    static void readPacketRecord(const uint8_t* data, PacketRecord& pr) {
        pr.timestampSeconds = *(const uint32_t*)&data[0];
        pr.timestampSubSeconds = *(const uint32_t*)&data[4];
        pr.captureLength = *(const uint32_t*)&data[8];
        pr.length = *(const uint32_t*)&data[12];
        if (pr.captureLength > 0) {
            pr.data = &data[16];
        }

        MMPR_DEBUG_LOG("--- [Packet Record %p] ---\n", (void*)data);
        MMPR_DEBUG_LOG("[PR] Timestamp Seconds: %u\n", pr.timestampSeconds);
        MMPR_DEBUG_LOG("[PR] Timestamp SubSeconds: %u\n", pr.timestampSubSeconds);
        MMPR_DEBUG_LOG("[PR] Capture Length: %u\n", pr.captureLength);
        MMPR_DEBUG_LOG("[PR] Length: %u\n", pr.length);
        MMPR_DEBUG_LOG("[PR] Data: %p\n", (void*)pr.data);
    }
};

} // namespace mmpr

#endif // MMPR_PCAPPARSER_H
