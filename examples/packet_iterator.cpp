#include <fpcap/fpcap.hpp>

#include <iostream>

using namespace std;

int main() {
    const string filepath = "tracefiles/example.pcap";

    // using range-based for loop with PacketReader
    fpcap::PacketReader reader(filepath);
    uint64_t processedPackets{0};
    for (const auto& packet : reader) {
        processedPackets++;
    }
    cout << "PacketReader: processed " << processedPackets << " packets" << endl;

    // using range-based for loop with Reader (unique_ptr)
    const auto readerPtr = fpcap::Reader::getReader(filepath);
    processedPackets = 0;
    for (const auto& packet : *readerPtr) {
        processedPackets++;
    }
    cout << "Reader:       processed " << processedPackets << " packets" << endl;

    return 0;
}
