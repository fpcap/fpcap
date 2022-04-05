#include <chrono>
#include <iostream>
#include <mmpr/pcapng/MMPcapNgReader.h>

using namespace std;
using namespace std::chrono;

int main() {
    for (const string& filepath :
         {"tracefiles/pcapng-example.pcapng", "tracefiles/many_interfaces-1.pcapng"}) {
        mmpr::MMPcapNgReader reader(filepath);
        reader.open();

        mmpr::Packet packet{};
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                processedPackets++;
            }
        }

        cout << "Metadata.Comment:  \"" << reader.getComment() << "\"" << endl;
        cout << "Metadata.OS:       \"" << reader.getOS() << "\"" << endl;
        cout << "Metadata.Hardware: \"" << reader.getHardware() << "\"" << endl;
        cout << "Metadata.UserAppl: \"" << reader.getUserApplication() << "\"" << endl;

        // close file descriptor and unmap memory
        reader.close();
    }

    return 0;
}
