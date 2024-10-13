#ifndef FPCAP_PCAPNG_HPP
#define FPCAP_PCAPNG_HPP

namespace fpcap::pcapng {
/**
 * Header Block Types, cf. https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.txt
 */
enum PcapNgBlockType : uint32_t {
    SECTION_HEADER_BLOCK = 0x0A0D0D0A,
    INTERFACE_DESCRIPTION_BLOCK = 1,
    PACKET_BLOCK = 2, // deprecated in newer PcapNG versions
    SIMPLE_PACKET_BLOCK = 3,
    NAME_RESOLUTION_BLOCK = 4,
    INTERFACE_STATISTICS_BLOCK = 5,
    ENHANCED_PACKET_BLOCK = 6,
    DECRYPTION_SECRETS_BLOCK = 10,
    CUSTOM_CAN_COPY_BLOCK = 0x00000BAD,
    CUSTOM_DO_NOT_COPY_BLOCK = 0x40000BAD
};
}

#endif // FPCAP_PCAPNG_HPP
