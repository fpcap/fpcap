#ifndef FPCAP_MODIFIEDPCAP_HPP
#define FPCAP_MODIFIEDPCAP_HPP

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
namespace fpcap::modified_pcap {
} // namespace fpcap::modified_pcap

#endif // FPCAP_MODIFIEDPCAP_HPP
