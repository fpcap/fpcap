#ifndef FPCAP_PCAPNGINTERFACESTATISTICSBLOCK_HPP
#define FPCAP_PCAPNGINTERFACESTATISTICSBLOCK_HPP

#include <cstdint>
#include <optional>

namespace fpcap::pcapng {
struct InterfaceStatisticsBlock {
    uint32_t blockTotalLength{0};
    uint32_t interfaceId{0};
    uint32_t timestampHigh{0};
    uint32_t timestampLow{0};

    // packet counters since the start of the capture, set if present in the block
    struct Options {
        std::optional<uint64_t> receivedPackets;         // isb_ifrecv
        std::optional<uint64_t> interfaceDroppedPackets; // isb_ifdrop
        std::optional<uint64_t> filterAcceptedPackets;   // isb_filteraccept
        std::optional<uint64_t> osDroppedPackets;        // isb_osdrop
        std::optional<uint64_t> deliveredPackets;        // isb_usrdeliv
    } options{};
};
} // fpcap::pcapng

#endif // FPCAP_PCAPNGINTERFACESTATISTICSBLOCK_HPP
