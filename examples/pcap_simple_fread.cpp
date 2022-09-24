#include "mmpr/pcap/FReadPcapReader.h"
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main() {
    string filepath = "tracefiles/example.pcap";

    // open file, map to memory and measure execution time
    auto start = high_resolution_clock::now();
    mmpr::FReadPcapReader reader(filepath);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop - start);
    cout << "Open file in " << duration.count() << "ms" << endl;

    // read all packets from the capture and measure execution time
    start = high_resolution_clock::now();
    mmpr::Packet packet{};
    uint64_t processedPackets{0};
    while (!reader.isExhausted()) {
        if (reader.readNextPacket(packet)) {
            processedPackets++;
        }
    }
    stop = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(stop - start);

    cout << "Processed " << processedPackets << " packets in " << duration.count() << "ms"
         << endl;

    return 0;
}
