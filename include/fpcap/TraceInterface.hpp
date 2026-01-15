#ifndef FPCAP_TRACEINTERFACE_HPP
#define FPCAP_TRACEINTERFACE_HPP

#include <string>
#include <optional>

namespace fpcap {
struct TraceInterface {
    TraceInterface() = default;

    TraceInterface(const std::optional<std::string>& name,
                   const std::optional<std::string>& description,
                   const std::optional<std::string>& filter,
                   const std::optional<std::string>& os,
                   const uint16_t dataLinkType,
                   const uint32_t timestampResolution = 1000000 /* 10^6 */)
        : name(name),
          description(description),
          filter(filter),
          os(os),
          dataLinkType(dataLinkType),
          timestampResolution(timestampResolution) {
    }

    std::optional<std::string> name;
    std::optional<std::string> description;
    std::optional<std::string> filter;
    std::optional<std::string> os;
    uint16_t dataLinkType{0};
    uint32_t timestampResolution{1000000}; // default: microseconds (10^6)
};
} // namespace fpcap

#endif //FPCAP_TRACEINTERFACE_HPP
