#ifndef MMPR_PCAPNGBLOCKPARSER_H
#define MMPR_PCAPNGBLOCKPARSER_H

#include <mmpr/mmpr.h>

namespace mmpr {
class PcapNgBlockParser {
public:
    static void readSHB(const uint8_t* data, SectionHeaderBlock& shb);
    static void readIDB(const uint8_t* data, InterfaceDescriptionBlock& idb);
    static void readEPB(const uint8_t* data, EnhancedPacketBlock& epb);
    static void readPB(const uint8_t* data, PacketBlock& pb);
    static void readISB(const uint8_t* data, InterfaceStatisticsBlock& isb);
};
} // namespace mmpr

#endif // MMPR_PCAPNGBLOCKPARSER_H
