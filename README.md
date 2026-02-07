![](https://fpcap.net/images/fpcap_logo.svg)

# FPCAP - A fast and lightweight PCAP file reading library

[![build](https://github.com/fpcap/fpcap/actions/workflows/build.yml/badge.svg)](https://github.com/fpcap/fpcap/actions/workflows/build.yml)

## Features

- Memory-mapping Pcap & PcapNG reading
- Supported PcapNG block types:
    - Section Header Block
    - Interface Description Block
    - Enhanced Packet Block
    - Interface Statistics Block
- Rudimentary support for block options
- Zstd de-compression support (file-endings .zst or .zstd)

## Usage

```c++
#include <fpcap/fpcap.hpp>
...
fpcap::PacketReader reader("myfile.pcap");
for (const fpcap::Packet& packet : reader) {
    // Access packet header information
    // uint32_t timestampSeconds
    // uint32_t timestampMicroseconds
    // uint32_t captureLength
    // uint32_t length
    // uint16_t dataLinkType

    // Access the actual byte data
    const uint8_t* data = packet.data;
    ...
}
```

## Build

```shell
mkdir build && cd build
cmake ..
cmake --build . --target fpcap example-simple -- -j 4
```

## Benchmarks

### 25.09.2022

```
---------------------------------------------------------------------
Benchmark                           Time             CPU   Iterations
---------------------------------------------------------------------
fpcap (pcap)                 59666484 ns     12744900 ns           52
fpcap-fread (pcap)            9108406 ns      1318842 ns          457
fpcap (pcapng)               58144655 ns     12134124 ns           55
fpcap-fread (pcapng)          8729187 ns      1195401 ns          592
fpcap (pcapng.zst)            8381497 ns      1946854 ns          361
PcapPlusPlus (pcap)          56237054 ns     11692277 ns           60
PcapPlusPlus (pcapng)        58786941 ns     12942878 ns           51
PcapPlusPlus (pcapng.zstd)    9824016 ns      3027536 ns          235
libpcap (pcap)               56189614 ns     11405524 ns           59
libpcap (pcapng)             58584807 ns     11988455 ns           60
```
