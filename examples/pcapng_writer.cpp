#include <fpcap/filesystem/Writer.hpp>
#include <fpcap/fpcap.hpp>

using namespace std;

int main() {
    const string srcFilepath = "tracefiles/pcapng-example.pcapng";
    const string dstFilepath = "pcapng-example.copy.pcapng";

    fpcap::PacketReader reader(srcFilepath);
    const auto writer = fpcap::Writer::getWriter(dstFilepath, false);

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
