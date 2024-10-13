#ifndef FPCAP_MODIFIEDPCAPPACKETRECORD_HPP
#define FPCAP_MODIFIEDPCAPPACKETRECORD_HPP

#include <cstdint>

namespace fpcap::modified_pcap {
struct PacketRecord {
    uint32_t timestampSeconds{0}; // timestamp seconds
    uint32_t timestampSubSeconds{0}; // timestamp microseconds
    uint32_t captureLength{0}; // number of octets of packet saved in file
    uint32_t length{0}; // actual length of packet
    uint32_t interfaceIndex{0}; // index, in *capturing* machine's list of interfaces
    uint16_t protocol{0}; // Ethernet packet type
    uint8_t packetType{0}; // broadcast/multicast/etc. indication
    uint8_t padding{0}; // pad to a 4-byte boundary
    const uint8_t* data{nullptr};
};
} // namespace fpcap::modified_pcap

#endif // FPCAP_MODIFIEDPCAPPACKETRECORD_HPP
