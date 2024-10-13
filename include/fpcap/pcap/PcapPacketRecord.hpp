#ifndef FPCAP_PCAPPACKETRECORD_HPP
#define FPCAP_PCAPPACKETRECORD_HPP

#include <cstdint>

namespace fpcap::pcap {
struct PacketRecord {
    uint32_t timestampSeconds{0};
    uint32_t timestampSubSeconds{0};
    uint32_t captureLength{0};
    uint32_t length{0};
    const uint8_t* data{nullptr};
    bool dataDynamicallyAllocated{false};
};
} // namespace fpcap::pcap

#endif // FPCAP_PCAPPACKETRECORD_HPP
