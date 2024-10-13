#include <fpcap/pcapng/PcapNgReader.hpp>

#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main() {
    const string filepath = "tracefiles/pcapng-example.pcapng";

    const auto reader = fpcap::Reader::getReader(filepath);
    for (size_t i = 0; i < 10 && !reader->isExhausted(); ++i) {
        reader->readBlock();
    }

    return 0;
}
