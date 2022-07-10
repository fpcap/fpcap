#ifndef MMPR_MODIFIED_PCAP_H
#define MMPR_MODIFIED_PCAP_H

#include <cstdint>

namespace mmpr {
/**
 * "Modified" pcap
 * https://wiki.wireshark.org/Development/LibpcapFileFormat#modified-pcap
 *
 * Alexey Kuznetsov created patches to libpcap to add some extra fields to the record
 * header. (These patches were traditionally available at
 * http://ftp.sunet.se/pub/os/Linux/ip-routing/lbl-tools/ but are no longer available
 * there.) Within the Wireshark source code, this format is known simply as "modified
 * pcap."
 *
 * The magic bytes for this format are 0xa1b2cd34 (note the final two bytes). The file
 * header is otherwise the same as the standard libpcap header.
 */
struct ModifiedPcapFileHeader {
    uint16_t majorVersion{0}; // major version number
    uint16_t minorVersion{0}; // minor version number
    int32_t thiszone{0};      // GMT to local correction
    uint32_t sigfigs{0};      // accuracy of timestamps
    uint32_t snapLength{0};   // max length of captured packets, in octets
    uint32_t linkType{0};     // data link type
};

struct ModifiedPcapPacketRecord {
    uint32_t timestampSeconds{0};    // timestamp seconds
    uint32_t timestampSubSeconds{0}; // timestamp microseconds
    uint32_t captureLength{0};       // number of octets of packet saved in file
    uint32_t length{0};              // actual length of packet
    uint32_t interfaceIndex{0};      // index, in *capturing* machine's list of interfaces
    uint16_t protocol{0};            // Ethernet packet type
    uint8_t packetType{0};           // broadcast/multicast/etc. indication
    uint8_t padding{0};              // pad to a 4-byte boundary
    const uint8_t* data{nullptr};
};

} // namespace mmpr

#endif // MMPR_MODIFIED_PCAP_H
