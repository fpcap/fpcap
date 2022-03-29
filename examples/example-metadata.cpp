#include <chrono>
#include <fmt/format.h>
#include <iostream>
#include <mmpr/MMPcapNgReader.h>

using namespace std;
using namespace std::chrono;

int main() {
    for (const string& filepath : {"tracefiles/pcapng-example.pcapng", "tracefiles/many_interfaces-1.pcapng"}) {
        mmpr::MMPcapNgReader reader(filepath);
        reader.open();

        mmpr::Packet packet{};
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                processedPackets++;
            }
        }

        cout << fmt::format("Metadata.Comment:  {}", reader.getComment()) << endl;
        cout << fmt::format("Metadata.OS:       {}", reader.getOS()) << endl;
        cout << fmt::format("Metadata.Hardware: {}", reader.getHardware()) << endl;
        cout << fmt::format("Metadata.UserAppl: {}", reader.getUserApplication()) << endl;

        // close file descriptor and unmap memory
        reader.close();
    }

    return 0;
}
