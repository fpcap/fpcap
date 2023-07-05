#ifndef FPCAP_PCAPNGBLOCKOPTIONPARSER_HPP
#define FPCAP_PCAPNGBLOCKOPTIONPARSER_HPP

#include "fpcap/fpcap.hpp"
#include <cstddef>

namespace fpcap {

class PcapNgBlockOptionParser {
public:
    static void readOption(const uint8_t* data, pcapng::Option& option, size_t offset);
    static void readSHBOption(const uint8_t* data, pcapng::Option& option, size_t offset);
    static void
    readIDBBlockOption(const uint8_t* data, pcapng::Option& option, size_t offset);
    static void readEPBOption(const uint8_t* data, pcapng::Option& option, size_t offset);
    static void readISBOption(const uint8_t* data, pcapng::Option& option, size_t offset);

    /**
     * Parses a non zero terminated string from the option at option.value with length
     * option.length.
     * @param option the option containing the string value
     * @return string value
     */
    static std::string parseUTF8(const pcapng::Option& option);
};

} // namespace fpcap

#endif // FPCAP_PCAPNGBLOCKOPTIONPARSER_HPP
