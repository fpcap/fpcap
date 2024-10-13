#ifndef FPCAP_PCAPFILEHEADER_HPP
#define FPCAP_PCAPFILEHEADER_HPP

#include <cstdint>

namespace fpcap::pcap {
struct FileHeader {
    enum TimestampFormat { MICROSECONDS, NANOSECONDS } timestampFormat{MICROSECONDS};

    uint16_t majorVersion{0};
    uint16_t minorVersion{0};
    uint32_t snapLength{0};
    uint16_t dataLinkType{0};
    uint16_t fcsSequence{0};
};
} // namespace fpcap::pcap

#endif // FPCAP_PCAPFILEHEADER_HPP
