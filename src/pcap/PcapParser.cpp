#include "mmpr/pcap/PcapParser.hpp"

namespace mmpr {

void PcapParser::readFileHeader(const uint8_t* data, pcap::FileHeader& fh) {
    auto magicNumber = *(const uint32_t*)&data[0];
    if (magicNumber != PCAP_MICROSECONDS && magicNumber != PCAP_NANOSECONDS) {
        std::stringstream sstream;
        sstream << std::hex << magicNumber;
        std::string hex = sstream.str();
        std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
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

    fh.majorVersion = *(const uint16_t*)&data[4];
    fh.minorVersion = *(const uint16_t*)&data[6];

    fh.snapLength = *(const uint32_t*)&data[16];
    fh.linkType = *(const uint16_t*)&data[20];
    fh.fcsSequence = *(const uint16_t*)&data[22];

    MMPR_DEBUG_LOG_1("--- [File Header %p] ---\n", (void*)data);
    MMPR_DEBUG_LOG_1("[FH] Timestamp Format: %s\n",
                     fh.timestampFormat == pcap::FileHeader::MICROSECONDS
                         ? "MICROSECONDS"
                         : "NANOSECONDS");
    MMPR_DEBUG_LOG_2("[FH] Version: %u.%u\n", fh.majorVersion, fh.minorVersion);
    MMPR_DEBUG_LOG_1("[FH] Snap Length: %u\n", fh.snapLength);
    MMPR_DEBUG_LOG_1("[FH] FCS Sequence: %u\n", fh.fcsSequence);
    MMPR_DEBUG_LOG_1("[FH] Link Type: %u\n", fh.linkType);
}

void PcapParser::readPacketRecord(const uint8_t* data, pcap::PacketRecord& pr) {
    pr.timestampSeconds = *(const uint32_t*)&data[0];
    pr.timestampSubSeconds = *(const uint32_t*)&data[4];
    pr.captureLength = *(const uint32_t*)&data[8];
    pr.length = *(const uint32_t*)&data[12];
    if (pr.captureLength > 0) {
        pr.data = &data[16];
    }

    MMPR_DEBUG_LOG_1("--- [Packet Record %p] ---\n", (void*)data);
    MMPR_DEBUG_LOG_1("[PR] Timestamp Seconds: %u\n", pr.timestampSeconds);
    MMPR_DEBUG_LOG_1("[PR] Timestamp SubSeconds: %u\n", pr.timestampSubSeconds);
    MMPR_DEBUG_LOG_1("[PR] Capture Length: %u\n", pr.captureLength);
    MMPR_DEBUG_LOG_1("[PR] Length: %u\n", pr.length);
    MMPR_DEBUG_LOG_1("[PR] Data: %p\n", (void*)pr.data);
}

} // namespace mmpr
