#include <fpcap/pcap/PcapReader.hpp>
#include <chrono>
#include <fpcap/filesystem/Writer.hpp>

using namespace std;
using namespace std::chrono;

int main() {
    const string srcFilepath = "tracefiles/example.pcap";
    const string dstFilepath = "example.copy.pcap";

    const auto reader = fpcap::Reader::getReader(srcFilepath);
    const auto writer = fpcap::Writer::getWriter(dstFilepath);

    fpcap::Packet packet{};
    uint64_t processedPackets{0};
    while (!reader->isExhausted()) {
        if (reader->readNextPacket(packet)) {
            writer->write(packet);
            processedPackets++;
        }
    }

    return 0;
}
