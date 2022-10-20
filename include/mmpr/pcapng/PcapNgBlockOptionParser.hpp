#ifndef MMPR_PCAPNGBLOCKOPTIONPARSER_HPP
#define MMPR_PCAPNGBLOCKOPTIONPARSER_HPP

#include "mmpr/mmpr.hpp"
#include <cstddef>

namespace mmpr {

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
    static std::string parseUTF8(const pcapng::Option& option) {
        return std::string(reinterpret_cast<const char*>(option.value), option.length);
    }
};

} // namespace mmpr

#endif // MMPR_PCAPNGBLOCKOPTIONPARSER_HPP
