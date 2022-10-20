#ifndef MMPR_MMPR_H
#define MMPR_MMPR_H

#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
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

/**
 * Magic numbers for implemented file formats.
 */
enum MagicNumber : uint32_t {
    PCAP_MICROSECONDS = 0xA1B2C3D4,
    PCAP_NANOSECONDS = 0xA1B23C4D,
    PCAPNG = 0x0A0D0D0A,
    ZSTD = 0xFD2FB528,
    MODIFIED_PCAP = 0xA1B2CD34,
    MODIFIED_PCAP_BE = 0x34CDB2A1
};

class Reader {
public:
    virtual ~Reader() = default;

    virtual bool isExhausted() const = 0;
    virtual bool readNextPacket(Packet& packet) = 0;
    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const = 0;
    virtual size_t getCurrentOffset() const = 0;
    virtual uint16_t getDataLinkType() const = 0;
    virtual std::vector<TraceInterface> getTraceInterfaces() const = 0;
    virtual TraceInterface getTraceInterface(size_t id) const = 0;

    static std::unique_ptr<Reader> getReader(const std::string& filepath);
};

class Writer {
public:
    virtual ~Writer() = default;

    virtual void write(const Packet& packet) = 0;

    static std::unique_ptr<Writer> getWriter(const std::string& filepath);
};

/**
 * PCAP
 */
namespace pcap {

struct FileHeader {
    enum TimestampFormat { MICROSECONDS, NANOSECONDS } timestampFormat{MICROSECONDS};
    uint16_t majorVersion{0};
    uint16_t minorVersion{0};
    uint32_t snapLength{0};
    uint16_t linkType{0};
    uint16_t fcsSequence{0};
};

struct PacketRecord {
    uint32_t timestampSeconds{0};
    uint32_t timestampSubSeconds{0};
    uint32_t captureLength{0};
    uint32_t length{0};
    const uint8_t* data{nullptr};
    bool dataDynamicallyAllocated{false};
};

} // namespace pcap

/**
 * "Modified" pcap
 * https://wiki.wireshark.org/Development/LibpcapFileFormat#modified-pcap
 *
 * Alexey Kuznetsov created patches to libpcap to add some extra fields to the record
 * header. (These patches were traditionally available at
 * http://ftp.sunet.se/pub/os/Linux/ip-routing/lbl-tools/ but are no longer available
 * there.) Within the Wireshark source code, this format is known simply as "modified
 * pcap."
 *
 * The magic bytes for this format are 0xa1b2cd34 (note the final two bytes). The file
 * header is otherwise the same as the standard libpcap header.
 */
namespace modified_pcap {

struct FileHeader {
    uint16_t majorVersion{0}; // major version number
    uint16_t minorVersion{0}; // minor version number
    int32_t thiszone{0};      // GMT to local correction
    uint32_t sigfigs{0};      // accuracy of timestamps
    uint32_t snapLength{0};   // max length of captured packets, in octets
    uint32_t linkType{0};     // data link type
};

struct PacketRecord {
    uint32_t timestampSeconds{0};    // timestamp seconds
    uint32_t timestampSubSeconds{0}; // timestamp microseconds
    uint32_t captureLength{0};       // number of octets of packet saved in file
    uint32_t length{0};              // actual length of packet
    uint32_t interfaceIndex{0};      // index, in *capturing* machine's list of interfaces
    uint16_t protocol{0};            // Ethernet packet type
    uint8_t packetType{0};           // broadcast/multicast/etc. indication
    uint8_t padding{0};              // pad to a 4-byte boundary
    const uint8_t* data{nullptr};
};

} // namespace modified_pcap

/**
 * PCAP-NG
 */
namespace pcapng {

/**
 * Header Block Types, cf. https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.txt
 */
#define MMPR_SECTION_HEADER_BLOCK 0x0A0D0D0A
#define MMPR_INTERFACE_DESCRIPTION_BLOCK 1
#define MMPR_PACKET_BLOCK 2 // deprecated in newer PcapNG versions
#define MMPR_SIMPLE_PACKET_BLOCK 3
#define MMPR_NAME_RESOLUTION_BLOCK 4
#define MMPR_INTERFACE_STATISTICS_BLOCK 5
#define MMPR_ENHANCED_PACKET_BLOCK 6
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

#define MMPR_BLOCK_OPTION_IDB_NAME 2
#define MMPR_BLOCK_OPTION_IDB_DESCRIPTION 3
#define MMPR_BLOCK_OPTION_IDB_TSRESOL 9
#define MMPR_BLOCK_OPTION_IDB_FILTER 11
#define MMPR_BLOCK_OPTION_IDB_OS 12

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
        std::optional<std::string> name;
        std::optional<std::string> description;
        std::optional<std::string> filter;
        std::optional<std::string> os;
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

struct PacketBlock {
    uint32_t blockTotalLength{0};
    uint16_t interfaceId{0};
    uint16_t dropsCount{0};
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

} // namespace pcapng

} // namespace mmpr

#endif // MMPR_MMPR_H
