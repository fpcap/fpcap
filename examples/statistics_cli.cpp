#include "fpcap/pcapng/PcapNgReader.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main(int argc, char** argv) {
    vector<string> pcapFiles;

    for (size_t i = 1; i < argc; ++i) {
        pcapFiles.emplace_back(argv[i]);
    }

    if (pcapFiles.size() <= 0) {
        cout << "Error: you have to provide at least one input file!" << endl;
        return EXIT_FAILURE;
    }

    // sort files for deterministic results
    std::sort(pcapFiles.begin(), pcapFiles.end());

    // metrics to count
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t capturedBytes = 0;
    uint64_t totalFileSize = 0;

    auto start = high_resolution_clock::now();

    for (const auto& pcapFile : pcapFiles) {
        std::unique_ptr<fpcap::Reader> reader = fpcap::Reader::getReader(pcapFile);
        totalFileSize += reader->getFileSize();

        fpcap::Packet packet;
        while (!reader->isExhausted()) {
            if (reader->readNextPacket(packet)) {
                ++packets;
                bytes += packet.length;
                capturedBytes += packet.captureLength;
            }
        }
    }

    auto stop = high_resolution_clock::now();
    uint64_t duration = duration_cast<nanoseconds>(stop - start).count();

    cout << "Time elapsed: " << duration << "ns" << endl;
    cout << "Packets: " << packets << endl;
    cout << "Bytes: " << bytes << endl;
    cout << "Bytes (captured): " << capturedBytes << endl;

    cout << (double)packets * 1000000000 / duration << " packets/s" << endl;
    cout << (double)totalFileSize * 1000000000 / duration << " bytes/s" << endl;

    return 0;
}
