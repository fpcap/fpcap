#ifndef FPCAP_WRITER_HPP
#define FPCAP_WRITER_HPP

#include <fpcap/Packet.hpp>

#include <memory>
#include <string>

namespace fpcap {
class Writer {
public:
    virtual ~Writer() = default;

    virtual void write(const Packet& packet) = 0;

    static std::unique_ptr<Writer> getWriter(const std::string& filepath,
                                             bool append = false);
};
} // namespace fpcap

#endif // FPCAP_WRITER_HPP
