#ifndef FPCAP_PCAPNGBLOCKOPTION_HPP
#define FPCAP_PCAPNGBLOCKOPTION_HPP

#include <cstdint>

/**
 * Block Options
 */
#define FPCAP_BLOCK_OPTION_END_OF_OPT 0
#define FPCAP_BLOCK_OPTION_COMMENT 1
#define FPCAP_BLOCK_OPTION_SHB_HARDWARE 2
#define FPCAP_BLOCK_OPTION_SHB_OS 3
#define FPCAP_BLOCK_OPTION_SHB_USERAPPL 4

#define FPCAP_BLOCK_OPTION_IDB_NAME 2
#define FPCAP_BLOCK_OPTION_IDB_DESCRIPTION 3
#define FPCAP_BLOCK_OPTION_IDB_TSRESOL 9
#define FPCAP_BLOCK_OPTION_IDB_FILTER 11
#define FPCAP_BLOCK_OPTION_IDB_OS 12

namespace fpcap::pcapng {
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
    uint32_t totalLength() const { return 4u + length + ((4u - length % 4u) % 4u); }
};
} // namespace fpcap::pcapng

#endif // FPCAP_PCAPNGBLOCKOPTION_HPP
