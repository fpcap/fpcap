#include <fpcap/fpcap.hpp>
#include <fpcap/filesystem/Writer.hpp>

using namespace std;

int main() {
    const string srcFilepath = "tracefiles/example.pcap";
    const string dstFilepath = "example.copy.pcap";

    fpcap::PacketReader reader(srcFilepath);
    const auto writer = fpcap::Writer::getWriter(dstFilepath);

    fpcap::Packet packet{};
    uint64_t processedPackets{0};
    while (not reader.isExhausted()) {
        if (reader.nextPacket(packet)) {
            writer->write(packet);
            processedPackets++;
        }
    }

    return 0;
}
