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