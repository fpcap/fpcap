#ifndef FPCAP_PCAPNGBLOCKPARSER_HPP
#define FPCAP_PCAPNGBLOCKPARSER_HPP

#include <fpcap/pcapng/PcapNgSectionHeaderBlock.hpp>
#include <fpcap/pcapng/PcapNgInterfaceDescriptionBlock.hpp>
#include <fpcap/pcapng/PcapNgEnhancedPacketBlock.hpp>
#include <fpcap/pcapng/PcapNgPacketBlock.hpp>
#include <fpcap/pcapng/PcapNgInterfaceStatisticsBlock.hpp>

namespace fpcap::pcapng {
class PcapNgBlockParser {
public:
    static void readSHB(const uint8_t* data, SectionHeaderBlock& shb);
    static void readIDB(const uint8_t* data, InterfaceDescriptionBlock& idb);
    static void readEPB(const uint8_t* data, EnhancedPacketBlock& epb);
    static void readPB(const uint8_t* data, PacketBlock& pb);
    static void readISB(const uint8_t* data, InterfaceStatisticsBlock& isb);
};
} // namespace fpcap::pcapng

#endif // FPCAP_PCAPNGBLOCKPARSER_HPP
