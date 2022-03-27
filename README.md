# MMPR - Memory Mapping PcapNg Reader
## Build
```shell
mkdir build && cd build
cmake ..
cmake --build . --target mmpr example-simple -- -j 4
```

## Requirements
- Boost (with filesystem module), tested with v1.71
