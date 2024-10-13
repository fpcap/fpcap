#ifndef FPCAP_PCAPNGBLOCKOPTION_HPP
#define FPCAP_PCAPNGBLOCKOPTION_HPP

#include <cstdint>

namespace fpcap::pcapng {
/**
 * Block Options
 */
enum BlockOptionType : uint16_t {
    END_OF_OPT = 0,
    COMMENT = 1,
    SHB_HARDWARE = 2,
    SHB_OS = 3,
    SHB_USERAPPL = 4,

    IDB_NAME = 2,
    IDB_DESCRIPTION = 3,
    IDB_TSRESOL = 9,
    IDB_FILTER = 11,
    IDB_OS = 12,
};

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
