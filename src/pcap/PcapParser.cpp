#include "fpcap/pcap/PcapParser.hpp"

#include <fpcap/Constants.hpp>
#include <fpcap/util.hpp>

#include <sstream>

namespace fpcap::pcap {

void PcapParser::readFileHeader(const uint8_t* data, pcap::FileHeader& fh) {
    const auto magicNumber = *reinterpret_cast<const uint32_t*>(&data[0]);
    if (magicNumber != PCAP_MICROSECONDS && magicNumber != PCAP_NANOSECONDS) {
        std::stringstream sstream;
        sstream << std::hex << magicNumber;
        const std::string hex = sstream.str();
        throw std::runtime_error(
            "Expected PCAP file header to start with magic numbers 0xA1B2C3D4 or "
            "0xA1B23C4D, but instead got: 0x" +
            hex);
    }

    if (magicNumber == 0xA1B2C3D4) {
        fh.timestampFormat = pcap::FileHeader::MICROSECONDS;
    } else {
        fh.timestampFormat = pcap::FileHeader::NANOSECONDS;
    }

    fh.majorVersion = *reinterpret_cast<const uint16_t*>(&data[4]);
    fh.minorVersion = *reinterpret_cast<const uint16_t*>(&data[6]);

    fh.snapLength = *reinterpret_cast<const uint32_t*>(&data[16]);
    fh.dataLinkType = *reinterpret_cast<const uint16_t*>(&data[20]);
    fh.fcsSequence = *reinterpret_cast<const uint16_t*>(&data[22]);

    FPCAP_DEBUG_LOG_1("--- [File Header %p] ---\n", reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[FH] Timestamp Format: %s\n",
                      fh.timestampFormat == pcap::FileHeader::MICROSECONDS
                          ? "MICROSECONDS"
                          : "NANOSECONDS");
    FPCAP_DEBUG_LOG_2("[FH] Version: %u.%u\n", fh.majorVersion, fh.minorVersion);
    FPCAP_DEBUG_LOG_1("[FH] Snap Length: %u\n", fh.snapLength);
    FPCAP_DEBUG_LOG_1("[FH] FCS Sequence: %u\n", fh.fcsSequence);
    FPCAP_DEBUG_LOG_1("[FH] Link Type: %u\n", fh.dataLinkType);
}

void PcapParser::readPacketRecord(const uint8_t* data, pcap::PacketRecord& pr) {
    pr.timestampSeconds = *reinterpret_cast<const uint32_t*>(&data[0]);
    pr.timestampSubSeconds = *reinterpret_cast<const uint32_t*>(&data[4]);
    pr.captureLength = *reinterpret_cast<const uint32_t*>(&data[8]);
    pr.length = *reinterpret_cast<const uint32_t*>(&data[12]);
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
