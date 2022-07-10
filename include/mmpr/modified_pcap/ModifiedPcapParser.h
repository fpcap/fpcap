#ifndef MMPR_RAWPARSER_H
#define MMPR_RAWPARSER_H

#include "mmpr/mmpr.h"
#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace mmpr {
class ModifiedPcapParser {
public:
    /**
     * Appears to be same as standard PCAP header
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
     * 20 |                           Link Type                           |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */
    static void readFileHeader(const uint8_t* data, ModifiedPcapFileHeader& mpfh) {
        auto magicNumber = *(uint32_t*)&data[0];
        if (magicNumber != MMPR_MAGIC_NUMBER_MODIFIED_PCAP) {
            std::stringstream sstream;
            sstream << std::hex << magicNumber;
            std::string hex = sstream.str();
            std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
            throw std::runtime_error("Expected raw file header to start with magic "
                                     "numbers 0xA1B2CD34, but instead got: 0x" +
                                     hex);
        }

        mpfh.majorVersion = *(uint16_t*)&data[4];
        mpfh.minorVersion = *(uint16_t*)&data[6];
        mpfh.thiszone = *(int32_t*)&data[8];
        mpfh.sigfigs = *(uint32_t*)&data[12];
        mpfh.snapLength = *(uint32_t*)&data[16];
        mpfh.linkType = *(uint32_t*)&data[20];

        MMPR_DEBUG_LOG("--- [Modified PCAP File Header %p] ---\n", (void*)data);
        MMPR_DEBUG_LOG_2("[MPFH] Version: %u.%u\n", mpfh.majorVersion, mpfh.minorVersion);
        MMPR_DEBUG_LOG("[MPFH] This Zone: %i\n", mpfh.thiszone);
        MMPR_DEBUG_LOG("[MPFH] Sigfigs: %u\n", mpfh.sigfigs);
        MMPR_DEBUG_LOG("[MPFH] Snap Length: %u\n", mpfh.snapLength);
        MMPR_DEBUG_LOG("[MPFH] Link Type: %u\n", mpfh.linkType);
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
     * 16 |                        Interface Index                        |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 20 |            Protocol           |  Packet Type  |    Padding    |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 24 /                                                               /
     *    /                          Packet Data                          /
     *    /                        variable length                        /
     *    /                                                               /
     *    +---------------------------------------------------------------+
     */
    static void readPacketRecord(const uint8_t* data, ModifiedPcapPacketRecord& mppr) {
        mppr.timestampSeconds = *(uint32_t*)&data[0];
        mppr.timestampSubSeconds = *(uint32_t*)&data[4];
        mppr.captureLength = *(uint32_t*)&data[8];
        mppr.length = *(uint32_t*)&data[12];

        mppr.interfaceIndex = *(uint32_t*)&data[16];
        mppr.protocol = *(uint16_t*)&data[20];
        mppr.packetType = data[22];
        mppr.padding = data[23];

        if (mppr.captureLength > 0) {
            mppr.data = &data[24];
        }

        MMPR_DEBUG_LOG("--- [Modified PCAP Packet Record %p] ---\n", (void*)data);
        MMPR_DEBUG_LOG("[MPPR] Timestamp Seconds: %u\n", mppr.timestampSeconds);
        MMPR_DEBUG_LOG("[MPPR] Timestamp SubSeconds: %u\n", mppr.timestampSubSeconds);
        MMPR_DEBUG_LOG("[MPPR] Capture Length: %u\n", mppr.captureLength);
        MMPR_DEBUG_LOG("[MPPR] Length: %u\n", mppr.length);
        MMPR_DEBUG_LOG("[MPPR] Interface Index: %u\n", mppr.interfaceIndex);
        MMPR_DEBUG_LOG("[MPPR] Protocol: %u\n", mppr.protocol);
        MMPR_DEBUG_LOG("[MPPR] Packet Type: %u\n", mppr.packetType);
        MMPR_DEBUG_LOG("[MPPR] Padding: %u\n", mppr.padding);
        MMPR_DEBUG_LOG("[MPPR] Data: %p\n", (void*)mppr.data);
    }
};

} // namespace mmpr

#endif // MMPR_RAWPARSER_H
