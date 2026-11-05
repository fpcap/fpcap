#ifndef FPCAP_PCAPNGENHANCEDPACKETBLOCK_HPP
#define FPCAP_PCAPNGENHANCEDPACKETBLOCK_HPP

#include <cstdint>

namespace fpcap::pcapng {
struct EnhancedPacketBlock {
    uint32_t blockTotalLength{0};
    uint32_t interfaceId{0};
    uint32_t timestampHigh{0};
    uint32_t timestampLow{0};
    uint32_t capturePacketLength{0};
    uint32_t originalPacketLength{0};
    const uint8_t* packetData{nullptr};
    // unparsed options area, nullptr if the block has no options
    const uint8_t* options{nullptr};
    uint32_t optionsLength{0};
};
} // namespace fpcap::pcapng

#endif // FPCAP_PCAPNGENHANCEDPACKETBLOCK_HPP
