#include <benchmark/benchmark.h>

#include <PcapFileDevice.h>
#include <mmpr/MMPcapNgReader.h>
#include <mmpr/ZstdPcapNgReader.h>
#include <pcap.h>

#define SAMPLE_FILE tracefiles/pcapng-example.pcapng
#define Q(x) #x
#define QUOTE(x) Q(x)
#define ZST(file) QUOTE(file.zst)
#define ZSTD(file) QUOTE(file.zstd)

static void bmMmpr(benchmark::State& state) {
    mmpr::Packet packet;
    for (auto _ : state) {
        mmpr::MMPcapNgReader reader(QUOTE(SAMPLE_FILE));
        reader.open();

        uint64_t packetCount{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ++packetCount;
            }
        }

        reader.close();
    }
    benchmark::DoNotOptimize(packet);
}

static void bmMmprZst(benchmark::State& state) {
    mmpr::Packet packet;
    for (auto _ : state) {
        mmpr::ZstdPcapNgReader reader(ZST(SAMPLE_FILE));
        reader.open();

        uint64_t packetCount{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ++packetCount;
            }
        }

        reader.close();
    }
    benchmark::DoNotOptimize(packet);
}

static void bmPcapPlusPlus(benchmark::State& state) {
    pcpp::RawPacket packet;
    for (auto _ : state) {
        pcpp::PcapNgFileReaderDevice reader(QUOTE(SAMPLE_FILE));
        reader.open();

        uint64_t packetCount{0};
        while (reader.getNextPacket(packet)) {
            ++packetCount;
        }

        reader.close();
    }
    benchmark::DoNotOptimize(packet);
}

static void bmPcapPlusPlusZstd(benchmark::State& state) {
    pcpp::RawPacket packet;
    for (auto _ : state) {
        pcpp::PcapNgFileReaderDevice reader(ZSTD(SAMPLE_FILE));
        reader.open();

        uint64_t packetCount{0};
        while (reader.getNextPacket(packet)) {
            ++packetCount;
        }

        reader.close();
    }
    benchmark::DoNotOptimize(packet);
}

static void bmLibPcap(benchmark::State& state) {
    const std::uint8_t* packet;
    for (auto _ : state) {
        char errBuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcapHandle =
            pcap_open_offline(QUOTE(SAMPLE_FILE), errBuf);

        uint64_t packetCount{0};
        pcap_pkthdr header;
        while ((packet = pcap_next(pcapHandle, &header))) {
            ++packetCount;
        }

        pcap_close(pcapHandle);
    }
    benchmark::DoNotOptimize(packet);
}

BENCHMARK(bmMmpr)->Name("mmpr");
BENCHMARK(bmMmprZst)->Name("mmpr (.zst)");
BENCHMARK(bmPcapPlusPlus)->Name("PcapPlusPlus");
BENCHMARK(bmPcapPlusPlusZstd)->Name("PcapPlusPlus (.zstd)");
BENCHMARK(bmLibPcap)->Name("libpcap");