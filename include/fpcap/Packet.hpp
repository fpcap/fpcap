#ifndef FPCAP_PACKET_HPP
#define FPCAP_PACKET_HPP

#include <cstdint>

namespace fpcap {
struct Packet {
    uint32_t timestampSeconds{0};
    uint32_t timestampMicroseconds{0};
    uint32_t captureLength{0};
    uint32_t length{0};
    uint16_t dataLinkType{0};
    int32_t interfaceIndex{-1};
    const uint8_t* data{nullptr};
};
} // namespace fpcap

#endif // FPCAP_PACKET_HPP
