#ifndef MMPR_MMPR_H
#define MMPR_MMPR_H

#include "mmpr/modified_pcap.h"
#include "mmpr/pcap.h"
#include "mmpr/pcapng.h"
#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#if DEBUG
#define MMPR_DEBUG_LOG(format) printf(format);
#define MMPR_DEBUG_LOG_1(format, val) printf(format, val);
#define MMPR_DEBUG_LOG_2(format, val1, val2) printf(format, val1, val2);
#define MMPR_ASSERT(x) assert(x)
#else
#define MMPR_DEBUG_LOG(format) while (0)
#define MMPR_DEBUG_LOG_1(format, val) while (0)
#define MMPR_DEBUG_LOG_2(format, val1, val2) while (0)
#define MMPR_ASSERT(x) (void)(x)
#endif
#define MMPR_WARN(msg) fprintf(stderr, msg)
#define MMPR_WARN_1(msg, val) fprintf(stderr, msg, val)
#define MMPR_UNUSED(x) (void)(x)

#define MMPR_PAGE_SIZE 4096

#define MMPR_MAGIC_NUMBER_PCAP_MICROSECONDS 0xA1B2C3D4
#define MMPR_MAGIC_NUMBER_PCAP_NANOSECONDS 0xA1B23C4D
#define MMPR_MAGIC_NUMBER_PCAPNG 0x0A0D0D0A
#define MMPR_MAGIC_NUMBER_ZSTD 0xFD2FB528
#define MMPR_MAGIC_NUMBER_MODIFIED_PCAP 0xA1B2CD34

namespace mmpr {

struct Packet {
    ~Packet() {
        if (dataDynamicallyAllocated) {
            delete[] data;
        }
    }

    void swap(Packet& other) {
        std::swap(timestampSeconds, other.timestampSeconds);
        std::swap(timestampMicroseconds, other.timestampMicroseconds);
        std::swap(captureLength, other.captureLength);
        std::swap(length, other.length);
        std::swap(interfaceIndex, other.interfaceIndex);
        std::swap(data, other.data);
        std::swap(dataDynamicallyAllocated, other.dataDynamicallyAllocated);
    }

    uint32_t timestampSeconds{0};
    uint32_t timestampMicroseconds{0};
    uint32_t captureLength{0};
    uint32_t length{0};
    int interfaceIndex{-1};
    const uint8_t* data{nullptr};
    bool dataDynamicallyAllocated{false};
};

struct TraceInterface {
    TraceInterface(){};
    TraceInterface(std::optional<std::string> name,
                   std::optional<std::string> description,
                   std::optional<std::string> filter,
                   std::optional<std::string> os)
        : name(name), description(description), filter(filter), os(os) {}

    std::optional<std::string> name;
    std::optional<std::string> description;
    std::optional<std::string> filter;
    std::optional<std::string> os;
};

class FileReader {
protected:
    FileReader(const std::string& filepath);

    std::string mFilepath;

public:
    virtual ~FileReader() = default;

    virtual void open() = 0;
    virtual void close() = 0;
    virtual bool isExhausted() const = 0;
    virtual bool readNextPacket(Packet& packet) = 0;
    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const = 0;
    virtual size_t getCurrentOffset() const = 0;
    virtual uint16_t getDataLinkType() const = 0;
    virtual std::vector<TraceInterface> getTraceInterfaces() const = 0;
    virtual TraceInterface getTraceInterface(size_t id) const = 0;

    static std::unique_ptr<FileReader> getReader(const std::string& filepath);
};

} // namespace mmpr

#endif // MMPR_MMPR_H
