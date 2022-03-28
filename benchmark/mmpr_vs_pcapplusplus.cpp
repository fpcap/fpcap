#include <benchmark/benchmark.h>

#include <PcapFileDevice.h>
#include <mmpr/ZstdPcapNgReader.h>

static void BM_MMPR(benchmark::State& state) {
    for (auto _ : state) {
        mmpr::ZstdPcapNgReader reader("tracefiles/pcapng-example.pcapng.zstd");
        reader.open();

        uint64_t packetCount{0};
        mmpr::Packet packet;
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ++packetCount;
            }
        }

        reader.close();
    }
}

static void BM_PcapPlusPlus(benchmark::State& state) {
    for (auto _ : state) {
        pcpp::PcapNgFileReaderDevice reader("tracefiles/pcapng-example.pcapng.zst");
        reader.open();

        uint64_t packetCount{0};
        pcpp::RawPacket rawPacket;
        while (reader.getNextPacket(rawPacket)) {
            ++packetCount;
        }

        reader.close();
    }
}

BENCHMARK(BM_MMPR);
BENCHMARK(BM_PcapPlusPlus);
