#ifndef FPCAP_PCAPNGBLOCKPARSER_HPP
#define FPCAP_PCAPNGBLOCKPARSER_HPP

#include "fpcap/fpcap.hpp"

namespace fpcap {

class PcapNgBlockParser {
public:
    static void readSHB(const uint8_t* data, pcapng::SectionHeaderBlock& shb);
    static void readIDB(const uint8_t* data, pcapng::InterfaceDescriptionBlock& idb);
    static void readEPB(const uint8_t* data, pcapng::EnhancedPacketBlock& epb);
    static void readPB(const uint8_t* data, pcapng::PacketBlock& pb);
    static void readISB(const uint8_t* data, pcapng::InterfaceStatisticsBlock& isb);
};

} // namespace fpcap

#endif // FPCAP_PCAPNGBLOCKPARSER_HPP
