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

## Example

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

## Requirements

### Pre-install required

The following libraries need to be installed in the build environment:

- Zstd compression library (https://github.com/facebook/zstd), tested with v1.5.2

## Tests

### Submodules

- google/googletest in `v1.11.0` (https://github.com/google/googletest)

## Benchmarks

### Requirements

- libpcap

### Submodules

- google/benchmark in `v1.6.1` (https://github.com/google/benchmark)
- PcapPlusPlus with CMake support, clementperon/PcapPlusPlus on `cmake-ng`
  branch (https://github.com/clementperon/PcapPlusPlus.git)

### Disabling CPU Frequency Scaling

If you see this error:

```
***WARNING*** CPU scaling is enabled, the benchmark real time measurements may be noisy and will incur extra overhead.
```

you might want to disable the CPU frequency scaling while running the benchmark. Exactly how to do this depends on the
Linux distribution, desktop environment, and installed programs.

One simple option is to use the `cpupower` program to change the performance governor to "performance". This tool is
maintained along with the Linux kernel and provided by your distribution.

It must be run as root, like this:

```bash
sudo cpupower frequency-set --governor performance
```

After this you can verify that all CPUs are using the performance governor by running this command:

```bash
cpupower frequency-info -o proc
```

The benchmarks you subsequently run will have less variance.

Note that changing the governor in this way will not persist across reboots. To set the governor back, run the first
command again with the governor your system usually runs with, which varies.

If you find yourself doing this often, there are probably better options than running the commands above. Some
approaches allow you to do this without root access, or by using a GUI, etc. The Arch
Wiki [Cpu frequency scaling](https://wiki.archlinux.org/title/CPU_frequency_scaling) page is a good place to start
looking for options.

## Docker

```shell
cd docker/
docker build -t debian11-zstd-develop .
```

## Benchmark results

### 25.09.2022

```
---------------------------------------------------------------------
Benchmark                           Time             CPU   Iterations
---------------------------------------------------------------------
fpcap (pcap)                  59666484 ns     12744900 ns           52
fpcap-fread (pcap)             9108406 ns      1318842 ns          457
fpcap (pcapng)                58144655 ns     12134124 ns           55
fpcap-fread (pcapng)           8729187 ns      1195401 ns          592
fpcap (pcapng.zst)             8381497 ns      1946854 ns          361
PcapPlusPlus (pcap)          56237054 ns     11692277 ns           60
PcapPlusPlus (pcapng)        58786941 ns     12942878 ns           51
PcapPlusPlus (pcapng.zstd)    9824016 ns      3027536 ns          235
libpcap (pcap)               56189614 ns     11405524 ns           59
libpcap (pcapng)             58584807 ns     11988455 ns           60
```
