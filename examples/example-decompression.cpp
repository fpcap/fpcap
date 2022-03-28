#include <chrono>
#include <fmt/chrono.h>
#include <iostream>
#include <mmpr/ZstdPcapNgReader.h>

using namespace std;
using namespace std::chrono;

int main() {
    string filepath = "tracefiles/pcapng-example.pcapng.zst";

    // open file, map to memory and measure execution time
    auto start = high_resolution_clock::now();
    mmpr::ZstdPcapNgReader reader(filepath);
    reader.open();
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop - start);
    cout << fmt::format("Open and mapped file to memory in {}", duration) << endl;

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

    cout << fmt::format("Processed {} packets in {}", processedPackets, duration) << endl;

    // close file descriptor and unmap memory
    reader.close();

    return 0;
}
