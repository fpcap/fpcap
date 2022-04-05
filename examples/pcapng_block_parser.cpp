#include <mmpr/pcapng/MMPcapNgReader.h>

#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main() {
    string filepath = "tracefiles/pcapng-example.pcapng";

    mmpr::MMPcapNgReader reader(filepath);
    reader.open();

    for (size_t i = 0; i < 10 && !reader.isExhausted(); ++i) {
        reader.readBlock();
    }

    // close file descriptor and unmap memory
    reader.close();

    return 0;
}