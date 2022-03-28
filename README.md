# MMPR - Memory Mapping PcapNg Reader

## Features

- Memory-mapping PcapNg reading
- Supported PcapNg block types:
  - Section Header Block
  - Interface Description Block
  - Enhanced Packet Block
  - Interface Statistics Block
- Rudimentary support for block options
- Zstd de-compression support (file-endings .zst or .zstd)

## Build

```shell
mkdir build && cd build
cmake ..
cmake --build . --target mmpr example-simple -- -j 4
```

## Requirements

- Boost (with filesystem module), tested with v1.71
- Zstd compression library (https://github.com/facebook/zstd), tested with v1.5.2
- CMake-enabled version of PcapPlusPlus for benchmarks (https://github.com/seladb/PcapPlusPlus), tested with v21.11
    - Clone PcapPlusPlus to `libs/pcap-plus-plus` (TODO: add as proper submodule)