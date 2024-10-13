#ifndef FPCAP_MAGICNUMBER_HPP
#define FPCAP_MAGICNUMBER_HPP

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
} // namespace fpcap

#endif // FPCAP_MAGICNUMBER_HPP
