#ifndef MMPR_PCAPWRITER_H
#define MMPR_PCAPWRITER_H

#include "mmpr/filesystem/writing/FileWriter.h"
#include "mmpr/filesystem/writing/StreamFileWriter.h"
#include "mmpr/mmpr.h"

namespace mmpr {

template <typename TWriter>
class PcapWriter : public Writer {
    static_assert(std::is_base_of<FileWriter, TWriter>::value,
                  "TWriter must be a subclass of FileWriter");

public:
    PcapWriter(const std::string& filepath) : mWriter(filepath) { writePcapHeader(); }

    void write(const Packet& packet) override {
        struct PcapPacketHeader {
            uint32_t timestampSeconds;      /* timestamp seconds */
            uint32_t timestampMicroseconds; /* timestamp microseconds */
            uint32_t captureLength;         /* number of octets of packet saved in file */
            uint32_t length;                /* actual length of packet */
        };

        PcapPacketHeader pcapPacketHeader;
        pcapPacketHeader.timestampSeconds = packet.timestampSeconds;
        pcapPacketHeader.timestampMicroseconds = packet.timestampMicroseconds;
        pcapPacketHeader.captureLength = packet.captureLength;
        pcapPacketHeader.length = packet.length;

        mWriter.write((uint8_t*)&pcapPacketHeader, sizeof(pcapPacketHeader));
        mWriter.write(packet.data, packet.captureLength);
    }

private:
    void writePcapHeader() {
        struct PcapHeader {
            uint32_t magicNumber;  // magic number
            uint16_t versionMajor; // major version number
            uint16_t versionMinor; // minor version number
            int32_t thisZone;      // GMT to local correction
            uint32_t sigfigs;      // accuracy of timestamps
            uint32_t snapLength;   // max length of captured packets, in octets
            uint32_t dataLinkType; // data link type
        };

        PcapHeader pcapHeader;
        pcapHeader.magicNumber = PCAP_MICROSECONDS;
        pcapHeader.versionMajor = 2;
        pcapHeader.versionMinor = 4;
        pcapHeader.thisZone = 0;       // TODO account for timezone offset
        pcapHeader.sigfigs = 0;        // in practice all tools set this to 0
        pcapHeader.snapLength = 65535; // TODO support different snap lengths
        pcapHeader.dataLinkType = 1;   // TODO support more link types than DLT_EN10MB

        mWriter.write((uint8_t*)&pcapHeader, sizeof(pcapHeader));
    }

    TWriter mWriter;
};

typedef PcapWriter<StreamFileWriter> StreamPcapWriter;

} // namespace mmpr

#endif // MMPR_PCAPWRITER_H
