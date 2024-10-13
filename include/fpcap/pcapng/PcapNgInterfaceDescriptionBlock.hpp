#ifndef FPCAP_PCAPNGINTERFACEDESCRIPTIONBLOCK_HPP
#define FPCAP_PCAPNGINTERFACEDESCRIPTIONBLOCK_HPP

#include <cstdint>
#include <optional>
#include <string>

namespace fpcap::pcapng {
struct InterfaceDescriptionBlock {
    uint32_t blockTotalLength{0};
    uint16_t linkType{0};
    uint32_t snapLen{0};

    struct Options {
        uint32_t timestampResolution{1000000 /* 10^6 */};
        std::optional<std::string> name;
        std::optional<std::string> description;
        std::optional<std::string> filter;
        std::optional<std::string> os;
    } options{};
};
} // namespace fpcap::pcapng

#endif // FPCAP_PCAPNGINTERFACEDESCRIPTIONBLOCK_HPP
