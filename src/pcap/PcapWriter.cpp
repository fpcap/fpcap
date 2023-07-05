#include "fpcap/pcap/PcapWriter.hpp"

namespace fpcap {

template <typename TWriter>
PcapWriter<TWriter>::PcapWriter(const std::string& filepath) : mWriter(filepath) {
    writePcapHeader();
}

template <typename TWriter>
void PcapWriter<TWriter>::write(const Packet& packet) {
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

template <typename TWriter>
void PcapWriter<TWriter>::writePcapHeader() {
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

template class PcapWriter<StreamFileWriter>;

} // namespace fpcap
