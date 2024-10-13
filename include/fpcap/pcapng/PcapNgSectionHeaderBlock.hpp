#ifndef FPCAP_PCAPNGSECTIONHEADERBLOCK_HPP
#define FPCAP_PCAPNGSECTIONHEADERBLOCK_HPP

#include <cstdint>
#include <string>

namespace fpcap::pcapng {
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
} // namespace fpcap::pcapng

#endif // FPCAP_PCAPNGSECTIONHEADERBLOCK_HPP
