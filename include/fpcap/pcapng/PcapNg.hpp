#ifndef FPCAP_PCAPNG_HPP
#define FPCAP_PCAPNG_HPP

/**
 * Header Block Types, cf. https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.txt
 */
#define FPCAP_SECTION_HEADER_BLOCK 0x0A0D0D0A
#define FPCAP_INTERFACE_DESCRIPTION_BLOCK 1
#define FPCAP_PACKET_BLOCK 2 // deprecated in newer PcapNG versions
#define FPCAP_SIMPLE_PACKET_BLOCK 3
#define FPCAP_NAME_RESOLUTION_BLOCK 4
#define FPCAP_INTERFACE_STATISTICS_BLOCK 5
#define FPCAP_ENHANCED_PACKET_BLOCK 6
#define FPCAP_DECRYPTION_SECRETS_BLOCK 10
#define FPCAP_CUSTOM_CAN_COPY_BLOCK 0x00000BAD
#define FPCAP_CUSTOM_DO_NOT_COPY_BLOCK 0x40000BAD

#endif // FPCAP_PCAPNG_HPP
