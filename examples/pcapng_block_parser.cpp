#include "mmpr/pcapng/PcapNgReader.hpp"
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main() {
    string filepath = "tracefiles/pcapng-example.pcapng";

    auto reader = mmpr::Reader::getReader(filepath);
    for (size_t i = 0; i < 10 && !reader->isExhausted(); ++i) {
        reader->readBlock();
    }

    return 0;
}