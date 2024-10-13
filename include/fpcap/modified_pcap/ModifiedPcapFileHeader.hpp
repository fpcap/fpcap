#ifndef FPCAP_MODIFIEDPCAPFILEHEADER_HPP
#define FPCAP_MODIFIEDPCAPFILEHEADER_HPP

#include <cstdint>

namespace fpcap::modified_pcap {
struct FileHeader {
    uint16_t majorVersion{0}; // major version number
    uint16_t minorVersion{0}; // minor version number
    int32_t thiszone{0}; // GMT to local correction
    uint32_t sigfigs{0}; // accuracy of timestamps
    uint32_t snapLength{0}; // max length of captured packets, in octets
    uint32_t linkType{0}; // data link type
};
} // namespace fpcap::modified_pcap

#endif //FPCAP_MODIFIEDPCAPFILEHEADER_HPP
