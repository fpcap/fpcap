#include "fpcap/pcapng/PcapNgBlockOptionParser.hpp"

#include <fpcap/util.hpp>

#include <cmath>

namespace fpcap::pcapng {

/**
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Option Code              |         Option Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                       Option Value                            /
 * /              variable length, padded to 32 bits               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /                 . . . other options . . .                     /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Option Code == opt_endofopt |   Option Length == 0          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void PcapNgBlockOptionParser::readOption(const uint8_t* data,
                                         Option& option,
                                         const size_t offset) {
    option.type = *reinterpret_cast<const uint16_t*>(&data[offset]);
    option.length = *reinterpret_cast<const uint16_t*>(&data[offset + 2]);
    option.value = &data[offset + 4];
}

void PcapNgBlockOptionParser::readSHBOption(const uint8_t* data,
                                            Option& option,
                                            const size_t offset) {
    readOption(data, option, offset);

    switch (option.type) {
    case COMMENT:
        // opt_comment
        // TODO parse as UTF-8 string (not zero-terminated)
        FPCAP_DEBUG_LOG_2("[SHB][OPT] Comment: %.*s\n", option.length,
                          reinterpret_cast<const char*>(option.value));
        return;
    case SHB_HARDWARE:
        // shb_hardware
        // TODO parse as UTF-8 string (not zero-terminated)
        FPCAP_DEBUG_LOG_2("[SHB][OPT] Hardware: %.*s\n", option.length,
                          reinterpret_cast<const char*>(option.value));
        return;
    case SHB_OS:
        // shb_os
        // TODO parse as UTF-8 string (not zero-terminated)
        FPCAP_DEBUG_LOG_2("[SHB][OPT] OS: %.*s\n", option.length,
                          reinterpret_cast<const char*>(option.value));
        return;
    case SHB_USERAPPL:
        // shb_userappl
        // TODO parse as UTF-8 string (not zero-terminated)
        FPCAP_DEBUG_LOG_2("[SHB][OPT] User Application: %.*s\n", option.length,
                          reinterpret_cast<const char*>(option.value));
        return;
    default: {
        // custom option
    }
    }

    FPCAP_DEBUG_LOG_1("[SHB][OPT] Option Code/Type: %u\n", option.type);
    FPCAP_DEBUG_LOG_1("[SHB][OPT] Option Length: %u\n", option.length);
}

void PcapNgBlockOptionParser::readIDBBlockOption(const uint8_t* data,
                                                 Option& option,
                                                 const size_t offset) {
    readOption(data, option, offset);

    // TODO check if pre-defined options have the correct length, e.g., uint32_t = 4
    switch (option.type) {
    case IDB_NAME: {
        // if_name: name of the device used to capture data
        [[maybe_unused]] const std::string name = parseUTF8(option);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Device Name: %s\n", name.c_str());
        return;
    }
    case IDB_DESCRIPTION: {
        // if_description: description of the device used to capture data
        [[maybe_unused]] const std::string description = parseUTF8(option);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Device Description: %s\n", description.c_str());
        return;
    }
    case 4: {
        // if_IPv4addr
        // TODO parse if_IPv4addr
        break;
    }
    case 5: {
        // if_IPv6addr
        // TODO parse if_IPv6addr
        break;
    }
    case 6: {
        // if_MACaddr: Interface Hardware MAC address (48 bits), if available
        // TODO parse if_MACaddr
        break;
    }
    case 7: {
        // if_EUIaddr: Interface Hardware EUI address (64 bits), if available
        // TODO parse if_EUIaddr
        break;
    }
    case 8: {
        // if_speed: interface speed, in bits per second
        [[maybe_unused]] const uint64_t speed = *reinterpret_cast<const uint64_t*>(option.
            value);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Interface Speed: %lu bits/s\n",
                          static_cast<unsigned long>(speed));
        return;
    }
    case IDB_TSRESOL: {
        /* if_tsresol: resolution of timestamps
         *
         * The if_tsresol option identifies the resolution of timestamps. If the Most
         * Significant Bit is equal to zero, the remaining bits indicates the resolution
         * of the timestamp as a negative power of 10 (e.g. 6 means microsecond
         * resolution, timestamps are the number of microseconds since 1970-01-01 00:00:00
         * UTC). If the Most Significant Bit is equal to one, the remaining bits indicates
         * the resolution as negative power of 2 (e.g. 10 means 1/1024 of second). If this
         * option is not present, a resolution of 10^-6 is assumed (i.e. timestamps have
         * the same resolution of the standard 'libpcap' timestamps).
         */
        [[maybe_unused]] const auto tsresol = util::fromIfTsresolDouble(*option.value);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Timestamp resolution: %f\n", tsresol);
        return;
    }
    case 10: {
        // if_tzone: time zone for GMT support
        // TODO parse if_tzone
        break;
    }
    case IDB_FILTER: {
        /* if_filter: filter (e.g. "capture only TCP traffic") used to capture traffic
         *
         * The first octet of the Option Data keeps a code of the filter used (e.g. if
         * this is a libpcap string, or BPF bytecode, and more).
         */
        // skip first octet (filter code), interpret rest as string, cf. util::fromUTF8()
        [[maybe_unused]] const auto filter = std::string(
            reinterpret_cast<const char*>(&option.value[1]),
            option.length - 1);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Filter: %s\n", filter.c_str());
        return;
    }
    case IDB_OS: {
        // if_os: name of the operating system of the machine in which this interface is
        // installed
        [[maybe_unused]] const std::string os = parseUTF8(option);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] OS: %s\n", os.c_str());
        return;
    }
    case 13: {
        // if_fcslen: length of the Frame Check Sequence (in bits) for this interface
        [[maybe_unused]] const uint8_t fcslen = *option.value;
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Frame Check Sequence: 0x%01X\n", fcslen);
        return;
    }
    case 14: {
        // if_tsoffset: offset (in seconds) that must be added to the timestamp of
        // each packet to obtain the absolute timestamp of a packet
        [[maybe_unused]] const int64_t tsoffset = *reinterpret_cast<const int64_t*>(option
            .value);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Timestamp Offset: %li\n",
                          static_cast<long>(tsoffset));
        return;
    }
    case 15: {
        // if_hardware: description of the interface hardware
        // TODO parse as UTF-8 string (not zero-terminated)
        FPCAP_DEBUG_LOG_2("[IDB][OPT] Hardware: %.*s\n", option.length,
                          reinterpret_cast<const char*>(option.value));
        return;
    }
    case 16: {
        // if_txspeed: interface transmit speed in bits per second
        [[maybe_unused]] const uint64_t txspeed = *reinterpret_cast<const uint64_t*>(
            option.value);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Transmit Speed: %lu bits/s\n",
                          static_cast<unsigned long>(txspeed));
        return;
    }
    case 17: {
        // if_rxspeed: interface receive speed, in bits per second
        [[maybe_unused]] const uint64_t rxspeed = *reinterpret_cast<const uint64_t*>(
            option.value);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Receive Speed: %lu bits/s\n",
                          static_cast<unsigned long>(rxspeed));
        return;
    }
    default: {
        // custom option
    }
    }

    FPCAP_DEBUG_LOG_1("[IDB][OPT] Option Code/Type: %u\n", option.type);
    FPCAP_DEBUG_LOG_1("[IDB][OPT] Option Length: %u\n", option.length);
}

void PcapNgBlockOptionParser::readEPBOption(const uint8_t* data,
                                            Option& option,
                                            const size_t offset) {
    readOption(data, option, offset);

    // TODO check if pre-defined options have the correct length, e.g., uint32_t = 4
    switch (option.type) {
    case 2: {
        // epb_flags: 32-bit flags word containing link-layer information
        [[maybe_unused]] const uint32_t flags = *reinterpret_cast<const uint32_t*>(option.
            value);
        FPCAP_DEBUG_LOG_1("[IDB][OPT] Frame Check Sequence: 0x%04X\n", flags);
        return;
    }
    case 3: {
        // epb_hash: hash of the packet
        // TODO parse epb_hash
        break;
    }
    case 4: {
        // epb_dropcount: number of packets lost (by the interface and the operating
        // system)
        //                between this packet and the preceding one for the same interface
        //                or, for the first packet for an interface, between this packet
        //                and the start of the capture process
        [[maybe_unused]] const uint64_t dropCount = *reinterpret_cast<const uint64_t*>(
            option.value);
        FPCAP_DEBUG_LOG_1("[EPB][OPT] Drop Count: %lu packets\n",
                          static_cast<unsigned long>(dropCount));
        return;
    }
    case 5: {
        // epb_packetid: 64-bit unsigned integer that uniquely identifies the packet
        [[maybe_unused]] const uint64_t packetId = *reinterpret_cast<const uint64_t*>(
            option.value);
        FPCAP_DEBUG_LOG_1("[EPB][OPT] Packet ID: %lu\n",
                          static_cast<unsigned long>(packetId));
        return;
    }
    case 6: {
        // epb_queue: 32-bit unsigned integer that identifies on which queue of the
        // interface
        //            the specific packet was received
        [[maybe_unused]] const uint32_t queue = *reinterpret_cast<const uint32_t*>(option.
            value);
        FPCAP_DEBUG_LOG_1("[EPB][OPT] Queue: %u\n", queue);
        return;
    }
    case 7: {
        // epb_verdict: verdict of the packet; indicates what would be done with the
        // packet after
        //              processing it
        // TODO parse epb_verdict
        break;
    }
    default: {
        // custom option
    }
    }

    FPCAP_DEBUG_LOG_1("[EPB][OPT] Option Code/Type: %u\n", option.type);
    FPCAP_DEBUG_LOG_1("[EPB][OPT] Option Length: %u\n", option.length);
}

void PcapNgBlockOptionParser::readISBOption(const uint8_t* data,
                                            Option& option,
                                            const size_t offset) {
    readOption(data, option, offset);

    // TODO check if pre-defined options have the correct length, e.g., uint32_t = 4
    switch (option.type) {
    case 2: {
        // isb_starttime: time the capture started
        // TODO parse isb_starttime timestamp
        break;
    }
    case 3: {
        // isb_endtime: time the capture ended
        // TODO parse isb_starttime timestamp
        break;
    }
    case 4: {
        // isb_ifrecv: number of packets received from the physical interface
        //             starting from the beginning of the capture
        [[maybe_unused]] const uint64_t ifrecv = *reinterpret_cast<const uint64_t*>(option
            .value);
        FPCAP_DEBUG_LOG_1("[ISB][OPT] Received Packets: %lu",
                          static_cast<unsigned long>(ifrecv));
        return;
    }
    case 5: {
        // isb_ifdrop: number of packets dropped by the interface due to lack of
        //             resources starting from the beginning of the capture
        [[maybe_unused]] const uint64_t ifdrop = *reinterpret_cast<const uint64_t*>(option
            .value);
        FPCAP_DEBUG_LOG_1("[ISB][OPT] Dropped Packets (Interface): %lu",
                          static_cast<unsigned long>(ifdrop));
        return;
    }
    case 6: {
        // isb_filteraccept: number of packets accepted by filter starting from
        //                   the beginning of the capture
        [[maybe_unused]] const uint64_t filteraccept = *reinterpret_cast<const uint64_t*>(
            option.value);
        FPCAP_DEBUG_LOG_1("[ISB][OPT] Filtered Packets: %lu",
                          static_cast<unsigned long>(filteraccept));
        return;
    }
    case 7: {
        // isb_osdrop: number of packets dropped by the operating system starting
        //             from the beginning of the capture
        [[maybe_unused]] const uint64_t osdrop = *reinterpret_cast<const uint64_t*>(option
            .value);
        FPCAP_DEBUG_LOG_1("[ISB][OPT] Dropped Packets (OS): %lu",
                          static_cast<unsigned long>(osdrop));
        return;
    }
    case 8: {
        // isb_usrdeliv: number of packets delivered to the user starting from the
        //               beginning of the capture
        [[maybe_unused]] const uint64_t usrdeliv = *reinterpret_cast<const uint64_t*>(
            option.value);
        FPCAP_DEBUG_LOG_1("[ISB][OPT] Packets Delivered to User: %lu",
                          static_cast<unsigned long>(usrdeliv));
        return;
    }
    default: {
        // custom option
    }
    }

    FPCAP_DEBUG_LOG_1("[ISB][OPT] Option Code/Type: %u\n", option.type);
    FPCAP_DEBUG_LOG_1("[ISB][OPT] Option Length: %u\n", option.length);
}

std::string PcapNgBlockOptionParser::parseUTF8(const Option& option) {
    return std::string(reinterpret_cast<const char*>(option.value), option.length);
}

} // namespace fpcap
