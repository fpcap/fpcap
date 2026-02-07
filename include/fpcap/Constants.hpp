#ifndef FPCAP_CONSTANTS_HPP
#define FPCAP_CONSTANTS_HPP

#include <cstdint>

namespace fpcap {

/**
 * Magic numbers for implemented file formats.
 */
enum MagicNumber : uint32_t {
    PCAP_MICROSECONDS = 0xA1B2C3D4,
    PCAP_NANOSECONDS = 0xA1B23C4D,
    PCAPNG = 0x0A0D0D0A,
    ZSTD = 0xFD2FB528,
    MODIFIED_PCAP = 0xA1B2CD34,
    MODIFIED_PCAP_BE = 0x34CDB2A1
};

/**
 * Link-layer header types as defined by tcpdump/libpcap.
 * See https://www.tcpdump.org/linktypes.html
 */
enum DataLinkType : uint16_t {
    DLT_NULL = 0,       // BSD loopback
    DLT_EN10MB = 1,     // Ethernet
    DLT_IEEE802_5 = 6,  // Token Ring
    DLT_PPP = 9,        // Point-to-Point Protocol
    DLT_FDDI = 10,      // FDDI
    DLT_RAW = 101,      // Raw IP
    DLT_IEEE802_11 = 105, // IEEE 802.11 wireless
    DLT_LINUX_SLL = 113,  // Linux cooked capture
    DLT_LINUX_SLL2 = 276, // Linux cooked capture v2
};

} // namespace fpcap

#endif // FPCAP_CONSTANTS_HPP
