#ifndef MMPR_PCAPNG_H
#define MMPR_PCAPNG_H

#include <boost/optional.hpp>
#include <string>

/**
 * Header Block Types, cf. https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.txt
 */
#define MMPR_SECTION_HEADER_BLOCK 0x0A0D0D0A
#define MMPR_INTERFACE_DESCRIPTION_BLOCK 1
#define MMPR_PACKET_BLOCK 2  // deprecated in newer PcapNG versions
#define MMPR_SIMPLE_PACKET_BLOCK 3
#define MMPR_NAME_RESOLUTION_BLOCK 4
#define MMPR_INTERFACE_STATISTICS_BLOCK 5
#define MMPR_ENHANCED_PACKET_BLOCK 6
#define MMPR_DECRYPTION_SECRETS_BLOCK 10
#define MMPR_CUSTOM_CAN_COPY_BLOCK 0x00000BAD
#define MMPR_CUSTOM_DO_NOT_COPY_BLOCK 0x40000BAD

/**
 * Block Options
 */
#define MMPR_BLOCK_OPTION_END_OF_OPT 0
#define MMPR_BLOCK_OPTION_COMMENT 1
#define MMPR_BLOCK_OPTION_SHB_HARDWARE 2
#define MMPR_BLOCK_OPTION_SHB_OS 3
#define MMPR_BLOCK_OPTION_SHB_USERAPPL 4

#define MMPR_BLOCK_OPTION_IDB_NAME 2
#define MMPR_BLOCK_OPTION_IDB_DESCRIPTION 3
#define MMPR_BLOCK_OPTION_IDB_TSRESOL 9
#define MMPR_BLOCK_OPTION_IDB_FILTER 11
#define MMPR_BLOCK_OPTION_IDB_OS 12

namespace mmpr {

struct Option {
    uint16_t type{0};
    uint16_t length{0};
    const uint8_t* value{nullptr};

    /**
     * Calculates the total size of an option including padding (option values can have
     * variable length, but are padded to 32 bits).
     *
     * @return total length of option including padding
     */
    uint32_t totalLength() const { return 4 + length + ((4 - length % 4) % 4); }
};

struct SectionHeaderBlock {
    uint32_t blockTotalLength{0};
    uint16_t majorVersion{0};
    uint16_t minorVersion{0};
    int64_t sectionLength{0};
    struct Options {
        std::string comment;
        std::string os;
        std::string hardware;
        std::string userApplication;
    } options{};
};

struct InterfaceDescriptionBlock {
    uint32_t blockTotalLength{0};
    uint16_t linkType{0};
    uint32_t snapLen{0};
    struct Options {
        uint32_t timestampResolution{1000000 /* 10^6 */};
        boost::optional<std::string> name{boost::none};
        boost::optional<std::string> description{boost::none};
        boost::optional<std::string> filter{boost::none};
        boost::optional<std::string> os{boost::none};
    } options{};
};

struct EnhancedPacketBlock {
    uint32_t blockTotalLength{0};
    uint32_t interfaceId{0};
    uint32_t timestampHigh{0};
    uint32_t timestampLow{0};
    uint32_t capturePacketLength{0};
    uint32_t originalPacketLength{0};
    const uint8_t* packetData{nullptr};
};

struct PacketBlock {
    uint32_t blockTotalLength{0};
    uint16_t interfaceId{0};
    uint16_t dropsCount{0};
    uint32_t timestampHigh{0};
    uint32_t timestampLow{0};
    uint32_t capturePacketLength{0};
    uint32_t originalPacketLength{0};
    const uint8_t* packetData{nullptr};
};

struct InterfaceStatisticsBlock {
    uint32_t blockTotalLength{0};
    uint32_t interfaceId{0};
    uint32_t timestampHigh{0};
    uint32_t timestampLow{0};
};

} // namespace mmpr

#endif // MMPR_PCAPNG_H
