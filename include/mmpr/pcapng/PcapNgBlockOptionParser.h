#ifndef MMPR_PCAPNGBLOCKOPTIONPARSER_H
#define MMPR_PCAPNGBLOCKOPTIONPARSER_H

#include <cstddef>
#include <mmpr/mmpr.h>

namespace mmpr {
class PcapNgBlockOptionParser {
public:
    static void readOption(const uint8_t* data, Option& option, size_t offset);
    static void readSHBOption(const uint8_t* data, Option& option, size_t offset);
    static void readIDBBlockOption(const uint8_t* data, Option& option, size_t offset);
    static void readEPBOption(const uint8_t* data, Option& option, size_t offset);
    static void readISBOption(const uint8_t* data, Option& option, size_t offset);
};
} // namespace mmpr

#endif // MMPR_PCAPNGBLOCKOPTIONPARSER_H
