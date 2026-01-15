#ifndef FPCAP_PCAPNGSIMPLEPACKETBLOCK_HPP
#define FPCAP_PCAPNGSIMPLEPACKETBLOCK_HPP

#include <cstdint>

namespace fpcap::pcapng {
struct SimplePacketBlock {
    uint32_t blockTotalLength{0};
    uint32_t originalPacketLength{0};
    const uint8_t* packetData{nullptr};
};
} // namespace fpcap::pcapng

#endif // FPCAP_PCAPNGSIMPLEPACKETBLOCK_HPP
