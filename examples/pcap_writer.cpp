#include "mmpr/pcap/PcapReader.hpp"
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main() {
    string srcFilepath = "tracefiles/example.pcap";
    string dstFilepath = "example.copy.pcap";

    auto reader = mmpr::Reader::getReader(srcFilepath);
    auto writer = mmpr::Writer::getWriter(dstFilepath);

    mmpr::Packet packet{};
    uint64_t processedPackets{0};
    while (!reader->isExhausted()) {
        if (reader->readNextPacket(packet)) {
            writer->write(packet);
            processedPackets++;
        }
    }

    return 0;
}
