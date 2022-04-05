#include <mmpr/pcapng/PcapNgBlockOptionParser.h>

#include <mmpr/mmpr.h>
#include "util.h"
#include <cmath>

namespace mmpr {
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
                                         size_t offset) {
    option.type = *(const uint16_t*)&data[offset];
    option.length = *(const uint16_t*)&data[offset + 2];
    option.value = &data[offset + 4];
}

void PcapNgBlockOptionParser::readSHBOption(const uint8_t* data,
                                            Option& option,
                                            size_t offset) {
    readOption(data, option, offset);

    switch (option.type) {
    case MMPR_BLOCK_OPTION_COMMENT:
        // opt_comment
        // TODO parse as UTF-8 string (not zero-terminated)
        MMPR_DEBUG_LOG_2("[SHB][OPT] Comment: %.*s\n", option.length, option.value);
        return;
    case MMPR_BLOCK_OPTION_SHB_HARDWARE:
        // shb_hardware
        // TODO parse as UTF-8 string (not zero-terminated)
        MMPR_DEBUG_LOG_2("[SHB][OPT] Hardware: %.*s\n", option.length, option.value);
        return;
    case MMPR_BLOCK_OPTION_SHB_OS:
        // shb_os
        // TODO parse as UTF-8 string (not zero-terminated)
        MMPR_DEBUG_LOG_2("[SHB][OPT] OS: %.*s\n", option.length, option.value);
        return;
    case MMPR_BLOCK_OPTION_SHB_USERAPPL:
        // shb_userappl
        // TODO parse as UTF-8 string (not zero-terminated)
        MMPR_DEBUG_LOG_2("[SHB][OPT] User Application: %.*s\n", option.length,
                         option.value);
        return;
    default: {
        // custom option
    }
    }

    MMPR_DEBUG_LOG("[SHB][OPT] Option Code/Type: %u\n", option.type);
    MMPR_DEBUG_LOG("[SHB][OPT] Option Length: %u\n", option.length);
}

void PcapNgBlockOptionParser::readIDBBlockOption(const uint8_t* data,
                                                 Option& option,
                                                 size_t offset) {
    readOption(data, option, offset);

    // TODO check if pre-defined options have the correct length, e.g., uint32_t = 4
    switch (option.type) {
    case 2: {
        // if_name: name of the device used to capture data
        // TODO parse if_name as UTF-8 string (not zero-terminated)
        MMPR_DEBUG_LOG_2("[IDB][OPT] Device Name: %.*s\n", option.length, option.value);
        return;
    }
    case 3: {
        // if_description: description of the device used to capture data
        // TODO parse if_description as UTF-8 string (not zero-terminated)
        MMPR_DEBUG_LOG_2("[IDB][OPT] Device Description: %.*s\n", option.length,
                         option.value);
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
        const uint64_t speed = *(const uint64_t*)option.value;
        MMPR_UNUSED(speed);
        MMPR_DEBUG_LOG("[IDB][OPT] Interface Speed: %lu bits/s\n", speed);
        return;
    }
    case 9: {
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
        auto tsresol = util::fromIfTsresolDouble(*option.value);
        MMPR_UNUSED(tsresol);
        MMPR_DEBUG_LOG("[IDB][OPT] Timestamp resolution: %f\n", tsresol);
        return;
    }
    case 10: {
        // if_tzone: time zone for GMT support
        // TODO parse if_tzone
        break;
    }
    case 11: {
        // if_filter: filter (e.g. "capture only TCP traffic") used to capture traffic
        // TODO parse if_filter
        break;
    }
    case 12: {
        // if_os: name of the operating system of the machine in which this interface is
        // installed
        // TODO parse as UTF-8 string (not zero-terminated)
        MMPR_DEBUG_LOG_2("[IDB][OPT] OS: %.*s\n", option.length, option.value);
        return;
    }
    case 13: {
        // if_fcslen: length of the Frame Check Sequence (in bits) for this interface
        const uint8_t fcslen = *option.value;
        MMPR_UNUSED(fcslen);
        MMPR_DEBUG_LOG("[IDB][OPT] Frame Check Sequence: 0x%01X\n", fcslen);
        return;
    }
    case 14: {
        // if_tsoffset: offset (in seconds) that must be added to the timestamp of
        // each packet to obtain the absolute timestamp of a packet
        const int64_t tsoffset = *(const int64_t*)option.value;
        MMPR_UNUSED(tsoffset);
        MMPR_DEBUG_LOG("[IDB][OPT] Timestamp Offset: %li\n", tsoffset);
        return;
    }
    case 15: {
        // if_hardware: description of the interface hardware
        // TODO parse as UTF-8 string (not zero-terminated)
        MMPR_DEBUG_LOG_2("[IDB][OPT] Hardware: %.*s\n", option.length, option.value);
        return;
    }
    case 16: {
        // if_txspeed: interface transmit speed in bits per second
        const uint64_t txspeed = *(const uint64_t*)option.value;
        MMPR_UNUSED(txspeed);
        MMPR_DEBUG_LOG("[IDB][OPT] Transmit Speed: %lu bits/s\n", txspeed);
        return;
    }
    case 17: {
        // if_rxspeed: interface receive speed, in bits per second
        const uint64_t rxspeed = *(const uint64_t*)option.value;
        MMPR_UNUSED(rxspeed);
        MMPR_DEBUG_LOG("[IDB][OPT] Receive Speed: %lu bits/s\n", rxspeed);
        return;
    }
    default: {
        // custom option
    }
    }

    MMPR_DEBUG_LOG("[IDB][OPT] Option Code/Type: %u\n", option.type);
    MMPR_DEBUG_LOG("[IDB][OPT] Option Length: %u\n", option.length);
}

void PcapNgBlockOptionParser::readEPBOption(const uint8_t* data,
                                            Option& option,
                                            size_t offset) {
    readOption(data, option, offset);

    // TODO check if pre-defined options have the correct length, e.g., uint32_t = 4
    switch (option.type) {
    case 2: {
        // epb_flags: 32-bit flags word containing link-layer information
        uint32_t flags = *(const uint32_t*)option.value;
        MMPR_UNUSED(flags);
        MMPR_DEBUG_LOG("[IDB][OPT] Frame Check Sequence: 0x%04X\n", flags);
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
        uint64_t dropCount = *(const uint64_t*)option.value;
        MMPR_UNUSED(dropCount);
        MMPR_DEBUG_LOG("[EPB][OPT] Drop Count: %lu packets\n", dropCount);
        return;
    }
    case 5: {
        // epb_packetid: 64-bit unsigned integer that uniquely identifies the packet
        uint64_t packetId = *(const uint64_t*)option.value;
        MMPR_UNUSED(packetId);
        MMPR_DEBUG_LOG("[EPB][OPT] Packet ID: %lu\n", packetId);
        return;
    }
    case 6: {
        // epb_queue: 32-bit unsigned integer that identifies on which queue of the
        // interface
        //            the specific packet was received
        uint32_t queue = *(const uint32_t*)option.value;
        MMPR_UNUSED(queue);
        MMPR_DEBUG_LOG("[EPB][OPT] Queue: %u\n", queue);
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

    MMPR_DEBUG_LOG("[EPB][OPT] Option Code/Type: %u\n", option.type);
    MMPR_DEBUG_LOG("[EPB][OPT] Option Length: %u\n", option.length);
}

void PcapNgBlockOptionParser::readISBOption(const uint8_t* data,
                                            Option& option,
                                            size_t offset) {
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
        uint64_t ifrecv = *(const uint64_t*)option.value;
        MMPR_UNUSED(ifrecv);
        MMPR_DEBUG_LOG("[ISB][OPT] Received Packets: %lu", ifrecv);
        return;
    }
    case 5: {
        // isb_ifdrop: number of packets dropped by the interface due to lack of
        //             resources starting from the beginning of the capture
        uint64_t ifdrop = *(const uint64_t*)option.value;
        MMPR_UNUSED(ifdrop);
        MMPR_DEBUG_LOG("[ISB][OPT] Dropped Packets (Interface): %lu", ifdrop);
        return;
    }
    case 6: {
        // isb_filteraccept: number of packets accepted by filter starting from
        //                   the beginning of the capture
        uint64_t filteraccept = *(const uint64_t*)option.value;
        MMPR_UNUSED(filteraccept);
        MMPR_DEBUG_LOG("[ISB][OPT] Filtered Packets: %lu", filteraccept);
        return;
    }
    case 7: {
        // isb_osdrop: number of packets dropped by the operating system starting
        //             from the beginning of the capture
        uint64_t osdrop = *(const uint64_t*)option.value;
        MMPR_UNUSED(osdrop);
        MMPR_DEBUG_LOG("[ISB][OPT] Dropped Packets (OS): %lu", osdrop);
        return;
    }
    case 8: {
        // isb_usrdeliv: number of packets delivered to the user starting from the
        //               beginning of the capture
        uint64_t usrdeliv = *(const uint64_t*)option.value;
        MMPR_UNUSED(usrdeliv);
        MMPR_DEBUG_LOG("[ISB][OPT] Packets Delivered to User: %lu", usrdeliv);
        return;
    }
    default: {
        // custom option
    }
    }

    MMPR_DEBUG_LOG("[ISB][OPT] Option Code/Type: %u\n", option.type);
    MMPR_DEBUG_LOG("[ISB][OPT] Option Length: %u\n", option.length);
}
} // namespace mmpr
