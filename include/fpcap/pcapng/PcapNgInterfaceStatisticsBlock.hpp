#ifndef FPCAP_PCAPNGINTERFACESTATISTICSBLOCK_HPP
#define FPCAP_PCAPNGINTERFACESTATISTICSBLOCK_HPP

#include <cstdint>

namespace fpcap::pcapng {
struct InterfaceStatisticsBlock {
    uint32_t blockTotalLength{0};
    uint32_t interfaceId{0};
    uint32_t timestampHigh{0};
    uint32_t timestampLow{0};
};
} // fpcap::pcapng

#endif // FPCAP_PCAPNGINTERFACESTATISTICSBLOCK_HPP
