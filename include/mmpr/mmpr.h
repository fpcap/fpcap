#ifndef MMPR_MMPR_H
#define MMPR_MMPR_H

#include <boost/filesystem.hpp>
#include <cassert>
#include <cstdint>
#include <cstdio>

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

/**
 * Header Block Types, cf. https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.txt
 */
#define MMPR_SECTION_HEADER_BLOCK 0x0A0D0D0A
#define MMPR_INTERFACE_DESCRIPTION_BLOCK 1
#define MMPR_ENHANCED_PACKET_BLOCK 6
#define MMPR_SIMPLE_PACKET_BLOCK 3
#define MMPR_NAME_RESOLUTION_BLOCK 4
#define MMPR_INTERFACE_STATISTICS_BLOCK 5
#define MMPR_DECRYPTION_SECRETS_BLOCK 10
#define MMPR_CUSTOM_CAN_COPY_BLOCK 0x00000BAD
#define MMPR_CUSTOM_DO_NOT_COPY_BLOCK 0x40000BAD

/**
 * Block Options
 */
#define MMPR_BLOCK_OPTION_END_OF_OPT 0
#define MMPR_BLOCK_OPTION_COMMENT 1
#define MMPR_BLOCK_OPTION_SHB_HARDWARE 2
#define MMPR_BLOCK_OPTION_SHB_OS 3
#define MMPR_BLOCK_OPTION_SHB_USERAPPL 4

#define MMPR_BLOCK_OPTION_IDB_TSRESOL 9

namespace mmpr {
struct Packet {
    uint32_t timestampSeconds{0};
    uint32_t timestampMicroseconds{0};
    uint32_t captureLength{0};
    uint32_t length{0};
    const uint8_t* data{nullptr};
};

struct Option {
    uint16_t type{0};
    uint16_t length{0};
    const uint8_t* value{nullptr};

    /**
     * Calculates the total size of an option including padding (option values can have
     * variable length, but are padded to 32 bits).
     *
     * @return total length of option including padding
     */
    uint32_t totalLength() const { return 4 + length + ((4 - length % 4) % 4); }
};

struct SectionHeaderBlock {
    uint32_t blockTotalLength{0};
    uint16_t majorVersion{0};
    uint16_t minorVersion{0};
    int64_t sectionLength{0};
    struct Options {
        std::string comment;
        std::string os;
        std::string hardware;
        std::string userApplication;
    } options{};
};

struct InterfaceDescriptionBlock {
    uint32_t blockTotalLength{0};
    uint16_t linkType{0};
    uint32_t snapLen{0};
    struct Options {
        uint32_t timestampResolution{1000000 /* 10^6 */};
    } options{};
};

struct EnhancedPacketBlock {
    uint32_t blockTotalLength{0};
    uint32_t interfaceId{0};
    uint32_t timestampHigh{0};
    uint32_t timestampLow{0};
    uint32_t capturePacketLength{0};
    uint32_t originalPacketLength{0};
    const uint8_t* packetData{nullptr};
};

struct InterfaceStatisticsBlock {
    uint32_t blockTotalLength{0};
    uint32_t interfaceId{0};
    uint32_t timestampHigh{0};
    uint32_t timestampLow{0};
};

class PcapNgReader {
public:
    explicit PcapNgReader(const std::string& filepath) : mFilepath(filepath) {
        if (filepath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!boost::filesystem::exists(filepath)) {
            throw std::runtime_error("Cannot find file " +
                                     boost::filesystem::canonical(filepath).string());
        }
    };

    virtual void open() = 0;
    virtual bool isExhausted() const = 0;
    virtual bool readNextPacket(Packet& packet) = 0;
    virtual uint32_t readBlock() = 0;
    virtual void close() = 0;

    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const { return mFilepath; }
    virtual size_t getCurrentOffset() const = 0;
    virtual int getDataLinkType() const = 0;
    virtual std::string getComment() const { return mMetadata.comment; };
    virtual std::string getOS() const { return mMetadata.os; };
    virtual std::string getHardware() const { return mMetadata.hardware; };
    virtual std::string getUserApplication() const { return mMetadata.userApplication; };

protected:
    std::string mFilepath;
    struct PcapNgMetadata {
        std::string comment;
        std::string os;
        std::string hardware;
        std::string userApplication;
        // TODO support if_tsresol per interface
        uint32_t timestampResolution{1000000 /* 10^6 */};
    } mMetadata{};
};

} // namespace mmpr

#endif // MMPR_MMPR_H
