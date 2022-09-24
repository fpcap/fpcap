#ifndef MMPR_PCAPNGBLOCKPARSER_H
#define MMPR_PCAPNGBLOCKPARSER_H

#include "mmpr/mmpr.h"

namespace mmpr {

class PcapNgBlockParser {
public:
    static void readSHB(const uint8_t* data, pcapng::SectionHeaderBlock& shb);
    static void readIDB(const uint8_t* data, pcapng::InterfaceDescriptionBlock& idb);
    static void readEPB(const uint8_t* data, pcapng::EnhancedPacketBlock& epb);
    static void readPB(const uint8_t* data, pcapng::PacketBlock& pb);
    static void readISB(const uint8_t* data, pcapng::InterfaceStatisticsBlock& isb);
};

} // namespace mmpr

#endif // MMPR_PCAPNGBLOCKPARSER_H
