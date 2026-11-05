#include "fpcap/pcap/PcapParser.hpp"

#include <fpcap/Constants.hpp>
#include <fpcap/util.hpp>

#include <sstream>

namespace fpcap::pcap {

void PcapParser::readFileHeader(const uint8_t* data, pcap::FileHeader& fh) {
    const auto magicNumber = *reinterpret_cast<const uint32_t*>(&data[0]);
    switch (magicNumber) {
    case PCAP_MICROSECONDS:
    case PCAP_MICROSECONDS_SWAPPED:
        fh.timestampFormat = pcap::FileHeader::MICROSECONDS;
        break;
    case PCAP_NANOSECONDS:
    case PCAP_NANOSECONDS_SWAPPED:
        fh.timestampFormat = pcap::FileHeader::NANOSECONDS;
        break;
    default: {
        std::stringstream sstream;
        sstream << std::hex << magicNumber;
        const std::string hex = sstream.str();
        throw std::runtime_error(
            "Expected PCAP file header to start with magic numbers 0xA1B2C3D4 or "
            "0xA1B23C4D (in either byte order), but instead got: 0x" +
            hex);
    }
    }
    fh.byteSwapped = magicNumber == PCAP_MICROSECONDS_SWAPPED ||
                     magicNumber == PCAP_NANOSECONDS_SWAPPED;

    fh.majorVersion = *reinterpret_cast<const uint16_t*>(&data[4]);
    fh.minorVersion = *reinterpret_cast<const uint16_t*>(&data[6]);
    fh.snapLength = *reinterpret_cast<const uint32_t*>(&data[16]);
    auto linkTypeField = *reinterpret_cast<const uint32_t*>(&data[20]);
    if (fh.byteSwapped) {
        fh.majorVersion = util::byteSwap16(fh.majorVersion);
        fh.minorVersion = util::byteSwap16(fh.minorVersion);
        fh.snapLength = util::byteSwap32(fh.snapLength);
        linkTypeField = util::byteSwap32(linkTypeField);
    }
    fh.dataLinkType = static_cast<uint16_t>(linkTypeField & 0x0000FFFF);
    fh.fcsLengthPresent = (linkTypeField & 0x04000000) != 0;
    fh.fcsLength = static_cast<uint8_t>(linkTypeField >> 28);

    FPCAP_DEBUG_LOG_1("--- [File Header %p] ---\n", reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[FH] Timestamp Format: %s\n",
                      fh.timestampFormat == pcap::FileHeader::MICROSECONDS
                          ? "MICROSECONDS"
                          : "NANOSECONDS");
    FPCAP_DEBUG_LOG_2("[FH] Version: %u.%u\n", fh.majorVersion, fh.minorVersion);
    FPCAP_DEBUG_LOG_1("[FH] Snap Length: %u\n", fh.snapLength);
    FPCAP_DEBUG_LOG_1("[FH] FCS Length Present: %d\n", fh.fcsLengthPresent);
    FPCAP_DEBUG_LOG_1("[FH] FCS Length: %u\n", fh.fcsLength);
    FPCAP_DEBUG_LOG_1("[FH] Link Type: %u\n", fh.dataLinkType);
}

void PcapParser::readPacketRecord(const uint8_t* data,
                                  pcap::PacketRecord& pr,
                                  const bool byteSwapped) {
    pr.timestampSeconds = *reinterpret_cast<const uint32_t*>(&data[0]);
    pr.timestampSubSeconds = *reinterpret_cast<const uint32_t*>(&data[4]);
    pr.captureLength = *reinterpret_cast<const uint32_t*>(&data[8]);
    pr.length = *reinterpret_cast<const uint32_t*>(&data[12]);
    if (byteSwapped) {
        pr.timestampSeconds = util::byteSwap32(pr.timestampSeconds);
        pr.timestampSubSeconds = util::byteSwap32(pr.timestampSubSeconds);
        pr.captureLength = util::byteSwap32(pr.captureLength);
        pr.length = util::byteSwap32(pr.length);
    }
    if (pr.captureLength > 0) {
        pr.data = &data[16];
    }

    FPCAP_DEBUG_LOG_1("--- [Packet Record %p] ---\n",
                      reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[PR] Timestamp Seconds: %u\n", pr.timestampSeconds);
    FPCAP_DEBUG_LOG_1("[PR] Timestamp SubSeconds: %u\n", pr.timestampSubSeconds);
    FPCAP_DEBUG_LOG_1("[PR] Capture Length: %u\n", pr.captureLength);
    FPCAP_DEBUG_LOG_1("[PR] Length: %u\n", pr.length);
    FPCAP_DEBUG_LOG_1("[PR] Data: %p\n", reinterpret_cast<const void*>(pr.data));
}

} // namespace fpcap
