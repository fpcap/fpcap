#ifndef MMPR_STREAMPCAPPARSER_H
#define MMPR_STREAMPCAPPARSER_H

#include "mmpr/mmpr.h"
#include <algorithm>
#include <fstream>
#include <sstream>

namespace mmpr {
class StreamPcapParser {
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
    static void readFileHeader(std::ifstream& stream, FileHeader& fh) {
        uint32_t magicNumber;
        stream.read(reinterpret_cast<char*>(&magicNumber), sizeof magicNumber);
        if (magicNumber != 0xA1B2C3D4 && magicNumber != 0xA1B23C4D) {
            std::stringstream sstream;
            sstream << std::hex << magicNumber;
            std::string hex = sstream.str();
            std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
            throw std::runtime_error(
                "Expected PCAP file header to start with magic numbers 0xA1B2C3D4 or "
                "0xA1B23C4D, but instead got: 0x" +
                hex);
        }

        if (magicNumber == 0xA1B2C3D4) {
            fh.timestampFormat = FileHeader::MICROSECONDS;
        } else {
            fh.timestampFormat = FileHeader::NANOSECONDS;
        }

        stream.read(reinterpret_cast<char*>(&fh.majorVersion), sizeof fh.majorVersion);
        stream.read(reinterpret_cast<char*>(&fh.minorVersion), sizeof fh.minorVersion);

        // skip reserved fields
        stream.ignore(8);

        stream.read(reinterpret_cast<char*>(&fh.snapLength), sizeof fh.snapLength);
        stream.read(reinterpret_cast<char*>(&fh.linkType), sizeof fh.linkType);
        stream.read(reinterpret_cast<char*>(&fh.fcsSequence), sizeof fh.fcsSequence);

        MMPR_DEBUG_LOG("--- [File Header] ---\n");
        MMPR_DEBUG_LOG_1("[FH] Timestamp Format: %s\n",
                         fh.timestampFormat == FileHeader::MICROSECONDS ? "MICROSECONDS"
                                                                        : "NANOSECONDS");
        MMPR_DEBUG_LOG_2("[FH] Version: %u.%u\n", fh.majorVersion, fh.minorVersion);
        MMPR_DEBUG_LOG_1("[FH] Snap Length: %u\n", fh.snapLength);
        MMPR_DEBUG_LOG_1("[FH] FCS Sequence: %u\n", fh.fcsSequence);
        MMPR_DEBUG_LOG_1("[FH] Link Type: %u\n", fh.linkType);
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
    static void readPacketRecord(std::ifstream& stream, PacketRecord& pr) {
        stream.read(reinterpret_cast<char*>(&pr.timestampSeconds),
                    sizeof pr.timestampSeconds);
        stream.read(reinterpret_cast<char*>(&pr.timestampSubSeconds),
                    sizeof pr.timestampSubSeconds);
        stream.read(reinterpret_cast<char*>(&pr.captureLength), sizeof pr.captureLength);
        stream.read(reinterpret_cast<char*>(&pr.length), sizeof pr.length);

        if (pr.captureLength > 0) {
            auto data = new char[pr.captureLength];
            stream.read(data, pr.captureLength);
            pr.data = reinterpret_cast<uint8_t*>(data);
            pr.dataDynamicallyAllocated = true;
        }

        MMPR_DEBUG_LOG("--- [Packet Record] ---\n");
        MMPR_DEBUG_LOG_1("[PR] Timestamp Seconds: %u\n", pr.timestampSeconds);
        MMPR_DEBUG_LOG_1("[PR] Timestamp SubSeconds: %u\n", pr.timestampSubSeconds);
        MMPR_DEBUG_LOG_1("[PR] Capture Length: %u\n", pr.captureLength);
        MMPR_DEBUG_LOG_1("[PR] Length: %u\n", pr.length);
        MMPR_DEBUG_LOG_1("[PR] Data: %p\n", (void*)pr.data);
    }
};

} // namespace mmpr

#endif // MMPR_STREAMPCAPPARSER_H
