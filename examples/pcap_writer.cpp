#include "fpcap/pcap/PcapReader.hpp"
#include "fpcap/pcap/PcapWriter.hpp"

#include <chrono>

using namespace std;
using namespace std::chrono;

int main() {
    string srcFilepath = "tracefiles/example.pcap";
    string dstFilepath = "example.copy.pcap";

    auto reader = fpcap::Reader::getReader(srcFilepath);
    fpcap::StreamPcapWriter writer(dstFilepath);

    fpcap::Packet packet{};
    uint64_t processedPackets{0};
    while (!reader->isExhausted()) {
        if (reader->readNextPacket(packet)) {
            writer.write(packet);
            processedPackets++;
        }
    }

    return 0;
}
