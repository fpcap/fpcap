#ifndef MMPR_MMPR_H
#define MMPR_MMPR_H

#include <cassert>
#include <cstdint>
#include <mmpr/pcap.h>
#include <mmpr/pcapng.h>

#if DEBUG
#define MMPR_DEBUG_LOG(format, val) printf(format, val);
#define MMPR_DEBUG_LOG_2(format, val1, val2) printf(format, val1, val2);
#define MMPR_ASSERT(x) assert(x)
#else
#define MMPR_DEBUG_LOG(format, val) while (0)
#define MMPR_DEBUG_LOG_2(format, val1, val2) while (0)
#define MMPR_ASSERT(x) (void)(x)
#endif
#define MMPR_WARN(msg) fprintf(stderr, msg)
#define MMPR_WARN_1(msg, val) fprintf(stderr, msg, val)
#define MMPR_UNUSED(x) (void)(x)

#define MMPR_PAGE_SIZE 4096

namespace mmpr {

struct Packet {
    uint32_t timestampSeconds{0};
    uint32_t timestampMicroseconds{0};
    uint32_t captureLength{0};
    uint32_t length{0};
    int interfaceIndex{-1};
    const uint8_t* data{nullptr};
};

class FileReader {
protected:
    std::string mFilepath;

    FileReader(const std::string& filepath);

public:
    virtual void open() = 0;
    virtual void close() = 0;
    virtual bool isExhausted() const = 0;
    virtual bool readNextPacket(Packet& packet) = 0;
    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const = 0;
    virtual size_t getCurrentOffset() const = 0;
    virtual uint16_t getDataLinkType() const = 0;

    static FileReader* getReader(const std::string& filepath);
};

} // namespace mmpr

#endif // MMPR_MMPR_H
