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
                   const uint16_t dataLinkType)
        : name(name),
          description(description),
          filter(filter),
          os(os),
          dataLinkType(dataLinkType) {
    }

    std::optional<std::string> name;
    std::optional<std::string> description;
    std::optional<std::string> filter;
    std::optional<std::string> os;
    uint16_t dataLinkType{0};
};
} // namespace fpcap

#endif //FPCAP_TRACEINTERFACE_HPP
