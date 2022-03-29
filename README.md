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

### Pre-install required

The following libraries need to be installed in the build environment:

- Boost (with filesystem module), tested with v1.71
- Zstd compression library (https://github.com/facebook/zstd), tested with v1.5.2
- CMake-enabled version of PcapPlusPlus for benchmarks (https://github.com/seladb/PcapPlusPlus), tested with v21.11
    - Clone PcapPlusPlus to `libs/pcap-plus-plus` (TODO: add as proper submodule)

### Submodules

- google/benchmark in `v1.6.1` (https://github.com/google/benchmark)
- google/googletest in `v1.11.0` (https://github.com/google/googletest)
- fmtlib/fmt in `v8.1.1` (https://github.com/fmtlib/fmt)