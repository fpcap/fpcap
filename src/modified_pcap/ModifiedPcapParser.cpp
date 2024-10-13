#include "fpcap/modified_pcap/ModifiedPcapParser.hpp"

#include <fpcap/MagicNumber.hpp>
#include <fpcap/util.hpp>

#include <sstream>
#ifdef _WIN32
#include <winsock2.h>
#endif

namespace fpcap::modified_pcap {

void ModifiedPcapParser::readFileHeader(const uint8_t* data,
                                        modified_pcap::FileHeader& mpfh) {
    const auto magicNumber = *reinterpret_cast<const uint32_t*>(&data[0]);
    if (magicNumber != MODIFIED_PCAP && magicNumber != MODIFIED_PCAP_BE) {
        std::stringstream sstream;
        sstream << std::hex << magicNumber;
        const std::string hex = sstream.str();
        throw std::runtime_error(
            "Expected raw file header to start with magic numbers 0xA1B2CD34 or "
            "0x34CDB2A1, but instead got: 0x" +
            hex);
    }

    mpfh.majorVersion = *reinterpret_cast<const uint16_t*>(&data[4]);
    mpfh.minorVersion = *reinterpret_cast<const uint16_t*>(&data[6]);
    mpfh.thiszone = *reinterpret_cast<const int32_t*>(&data[8]);
    mpfh.sigfigs = *reinterpret_cast<const uint32_t*>(&data[12]);
    mpfh.snapLength = *reinterpret_cast<const uint32_t*>(&data[16]);
    mpfh.linkType = *reinterpret_cast<const uint32_t*>(&data[20]);

    if (magicNumber == MODIFIED_PCAP_BE) {
        mpfh.majorVersion = ntohs(mpfh.majorVersion);
        mpfh.minorVersion = ntohs(mpfh.minorVersion);
        mpfh.thiszone = ntohl(mpfh.thiszone);
        mpfh.sigfigs = ntohl(mpfh.sigfigs);
        mpfh.snapLength = ntohl(mpfh.snapLength);
        mpfh.linkType = ntohl(mpfh.linkType);
    }

    FPCAP_DEBUG_LOG_1("--- [Modified PCAP File Header %p] ---\n", (void*)data);
    FPCAP_DEBUG_LOG_2("[MPFH] Version: %u.%u\n", mpfh.majorVersion, mpfh.minorVersion);
    FPCAP_DEBUG_LOG_1("[MPFH] This Zone: %i\n", mpfh.thiszone);
    FPCAP_DEBUG_LOG_1("[MPFH] Sigfigs: %u\n", mpfh.sigfigs);
    FPCAP_DEBUG_LOG_1("[MPFH] Snap Length: %u\n", mpfh.snapLength);
    FPCAP_DEBUG_LOG_1("[MPFH] Link Type: %u\n", mpfh.linkType);
}

void ModifiedPcapParser::readPacketRecord(const uint8_t* data,
                                          modified_pcap::PacketRecord& mppr) {
    mppr.timestampSeconds = *reinterpret_cast<const uint32_t*>(&data[0]);
    mppr.timestampSubSeconds = *reinterpret_cast<const uint32_t*>(&data[4]);
    mppr.captureLength = *reinterpret_cast<const uint32_t*>(&data[8]);
    mppr.length = *reinterpret_cast<const uint32_t*>(&data[12]);

    mppr.interfaceIndex = *reinterpret_cast<const uint32_t*>(&data[16]);
    mppr.protocol = *reinterpret_cast<const uint16_t*>(&data[20]);
    mppr.packetType = data[22];
    mppr.padding = data[23];

    if (mppr.captureLength > 0) {
        mppr.data = &data[24];
    }

    FPCAP_DEBUG_LOG_1("--- [Modified PCAP Packet Record %p] ---\n",
                      reinterpret_cast<const void*>(data));
    FPCAP_DEBUG_LOG_1("[MPPR] Timestamp Seconds: %u\n", mppr.timestampSeconds);
    FPCAP_DEBUG_LOG_1("[MPPR] Timestamp SubSeconds: %u\n", mppr.timestampSubSeconds);
    FPCAP_DEBUG_LOG_1("[MPPR] Capture Length: %u\n", mppr.captureLength);
    FPCAP_DEBUG_LOG_1("[MPPR] Length: %u\n", mppr.length);
    FPCAP_DEBUG_LOG_1("[MPPR] Interface Index: %u\n", mppr.interfaceIndex);
    FPCAP_DEBUG_LOG_1("[MPPR] Protocol: %u\n", mppr.protocol);
    FPCAP_DEBUG_LOG_1("[MPPR] Packet Type: %u\n", mppr.packetType);
    FPCAP_DEBUG_LOG_1("[MPPR] Padding: %u\n", mppr.padding);
    FPCAP_DEBUG_LOG_1("[MPPR] Data: %p\n", reinterpret_cast<const void*>(mppr.data));
}

void ModifiedPcapParser::readPacketRecordBE(const uint8_t* data,
                                            modified_pcap::PacketRecord& mppr) {
    readPacketRecord(data, mppr);

    mppr.timestampSeconds = ntohl(mppr.timestampSeconds);
    mppr.timestampSubSeconds = ntohl(mppr.timestampSubSeconds);
    mppr.captureLength = ntohl(mppr.captureLength);
    mppr.length = ntohl(mppr.length);
    mppr.interfaceIndex = ntohl(mppr.interfaceIndex);
    mppr.protocol = ntohs(mppr.protocol);
}

} // namespace fpcap
