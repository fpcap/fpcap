#ifndef MMPR_PCAP_H
#define MMPR_PCAP_H

namespace mmpr {

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
};

}

#endif // MMPR_PCAP_H
