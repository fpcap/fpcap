![](https://fpcap.net/images/fpcap_logo.svg)

# FPCAP - A fast and lightweight PCAP file reading library

[![build](https://github.com/fpcap/fpcap/actions/workflows/build.yml/badge.svg)](https://github.com/fpcap/fpcap/actions/workflows/build.yml)
[![GitHub release](https://img.shields.io/github/v/release/fpcap/fpcap)](https://github.com/fpcap/fpcap/releases)
[![license](https://img.shields.io/github/license/fpcap/fpcap)](https://github.com/fpcap/fpcap/blob/main/LICENSE)

FPCAP is a modern, simple and lightweight C++ alternative to libpcap for reading packet capture files. It supports
advanced features like memory-mapping for efficiently processing large input files, without the overhead of a full-blown
packet capture framework. If you want to easily access packets from `.pcap` or `.pcapng` files, this library is for you.

## Features

- Memory-mapping Pcap & PcapNG reading
- Pcap & PcapNG writing
- Modified Pcap support
- Supported PcapNG block types:
    - Section Header Block
    - Interface Description Block
    - Enhanced Packet Block
    - Simple Packet Block
    - Interface Statistics Block
- Rudimentary support for block options
- Zstd de-compression support (file-endings .zst or .zstd)
- Range-based for loop iteration over packets
- Cross-platform: Linux, macOS, Windows

## Usage

### CMake Integration

```cmake
include(FetchContent)
FetchContent_Declare(
    fpcap
    GIT_REPOSITORY https://github.com/fpcap/fpcap.git
    GIT_TAG v0.2.0
)
FetchContent_MakeAvailable(fpcap)

target_link_libraries(your_target PRIVATE fpcap::fpcap)
```

### Reading

Reading packets from Pcap or PcapNG files via C++20 iterators:

```c++
#include <fpcap/fpcap.hpp>
...
fpcap::PacketReader reader("myfile.pcap");
for (const fpcap::Packet& packet : reader) {
    // packet.timestampSeconds, packet.captureLength, packet.data, ...
}
```

Or using the explicit reading API:

```c++
#include <fpcap/fpcap.hpp>
...
fpcap::PacketReader reader("myfile.pcap");
fpcap::Packet packet{};
while (!reader.isExhausted()) {
    if (reader.nextPacket(packet)) {
        // process packet
    }
}
```

### Writing

Writing packets to a Pcap file:

```c++
#include <fpcap/fpcap.hpp>
#include <fpcap/filesystem/Writer.hpp>
...
fpcap::PacketReader reader("input.pcap");
auto writer = fpcap::Writer::getWriter("output.pcap", false);

for (const fpcap::Packet& packet : reader) {
    writer->write(packet);
}
```

## Build

### Requirements

- C++20 compatible compiler:
    - GCC (tested on Debian 11/12/13 and Ubuntu)
    - Clang
    - MSVC (Visual Studio)
- CMake 3.16 or newer
- Linux, macOS or Windows

### Library only

```shell
cmake -B build .
cmake --build build --target fpcap
```

### Tests

```shell
cmake -DFPCAP_BUILD_TESTS=ON -B build .
cmake --build build --target fpcap_testcd build && ctest
```

### Examples

```shell
cmake -DFPCAP_BUILD_EXAMPLES=ON -B build .
cmake --build build
```

## Benchmarks

See [fpcap-benchmark](https://github.com/fpcap/fpcap-benchmark) for performance comparisons against other libraries.

## Contributing

Contributions and feedback are welcome! Feel free to open an issue or a merge request.

## License

This project is released into the public domain under the [Unlicense](LICENSE).
