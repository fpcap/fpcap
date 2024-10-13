#ifndef FPCAP_READER_HPP
#define FPCAP_READER_HPP

#include <fpcap/Packet.hpp>
#include <fpcap/TraceInterface.hpp>

#include <cstdint>
#include <stdexcept>
#include <vector>
#include <memory>

namespace fpcap {
class Reader {
public:
    virtual ~Reader() = default;

    virtual bool isExhausted() const = 0;
    virtual bool readNextPacket(Packet& packet) = 0;
    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const = 0;
    virtual size_t getCurrentOffset() const = 0;

    virtual std::string getComment() const {
        throw std::runtime_error("getComment() not implemented");
    }

    virtual std::string getOS() const {
        throw std::runtime_error("getOS() not implemented");
    }

    virtual std::string getHardware() const {
        throw std::runtime_error("getHardware() not implemented");
    }

    virtual std::string getUserApplication() const {
        throw std::runtime_error("getUserApplication() not implemented");
    }

    virtual uint32_t readBlock() {
        throw std::runtime_error("readBlock() not implemented");
    }

    virtual std::vector<TraceInterface> getTraceInterfaces() const {
        throw std::runtime_error("getTraceInterfaces() not implemented");
    }

    virtual TraceInterface getTraceInterface(size_t) const {
        throw std::runtime_error("getTraceInterface(size_t) not implemented");
    }

    static std::unique_ptr<Reader> getReader(const std::string& filepath);
};
} // namespace fpcap

#endif // FPCAP_READER_HPP
