#include "fpcap/pcap/PcapReader.hpp"

#include <fpcap/pcapng/PcapNgWriter.hpp>

using namespace std;

int main() {
    const string srcFilepath = "tracefiles/pcapng-example.pcapng";
    const string dstFilepath = "example.copy.pcapng";

    const auto reader = fpcap::Reader::getReader(srcFilepath);
    fpcap::StreamPcapNgWriter writer(dstFilepath);

    fpcap::pcapng::SectionHeaderBlock shb;
    shb.options.comment =
        "CLIENT_RANDOM E39B5BF4903C68684E8512FB2F60213E9EE843A0810B4982B607914D8092D482 "
        "95A5D39B02693BC1FB39254B179E9293007F6D37C66172B1EE4EF0D5E25CE1DABE878B6143DC3B26"
        "6883E51A75E99DF9";
    shb.options.os = "Linux 3.18.1-1-ARCH";
    shb.options.userApplication =
        "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)";
    writer.writeSHB(shb);

    fpcap::pcapng::InterfaceDescriptionBlock idb;
    idb.linkType = 0x0001;
    idb.snapLen = 262144u;
    idb.options.name = "lo";
    idb.options.filter = "tcp port 3306";
    idb.options.os = "Linux 3.18.1-1-ARCH";
    writer.writeIDB(idb);

    fpcap::Packet packet{};
    uint64_t processedPackets{0};
    while (!reader->isExhausted()) {
        if (reader->readNextPacket(packet)) {
            writer.writePacket(packet, 0);
            processedPackets++;
        }
    }

    return 0;
}
