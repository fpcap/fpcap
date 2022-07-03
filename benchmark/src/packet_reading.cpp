#include <benchmark/benchmark.h>

#include "mmpr/pcap/MMPcapReader.h"
#include "mmpr/pcapng/MMPcapNgReader.h"
#include "mmpr/pcapng/ZstdPcapNgReader.h"
#include <PcapFileDevice.h>
#include <pcap.h>

#define SAMPLE_PCAPNG_FILE tracefiles / pcapng - example.pcapng
#define SAMPLE_PCAP_FILE tracefiles / example.pcap
#define Q(x) #x
#define QUOTE(x) Q(x)
#define ZST(file) QUOTE(file.zst)
#define ZSTD(file) QUOTE(file.zstd)

static void bmMmprPcap(benchmark::State& state) {
    mmpr::Packet packet;
    for (auto _ : state) {
        mmpr::MMPcapReader reader(QUOTE(SAMPLE_PCAP_FILE));
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

static void bmMmprPcapNG(benchmark::State& state) {
    mmpr::Packet packet;
    for (auto _ : state) {
        mmpr::MMPcapNgReader reader(QUOTE(SAMPLE_PCAPNG_FILE));
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

static void bmMmprPcapNGZst(benchmark::State& state) {
    mmpr::Packet packet;
    for (auto _ : state) {
        mmpr::ZstdPcapNgReader reader(ZST(SAMPLE_PCAPNG_FILE));
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

static void bmPcapPlusPlusPcap(benchmark::State& state) {
    pcpp::RawPacket packet;
    for (auto _ : state) {
        pcpp::PcapFileReaderDevice reader(QUOTE(SAMPLE_PCAP_FILE));
        reader.open();

        uint64_t packetCount{0};
        while (reader.getNextPacket(packet)) {
            ++packetCount;
        }

        reader.close();
    }
    benchmark::DoNotOptimize(packet);
}

static void bmPcapPlusPlusPcapNG(benchmark::State& state) {
    pcpp::RawPacket packet;
    for (auto _ : state) {
        pcpp::PcapNgFileReaderDevice reader(QUOTE(SAMPLE_PCAPNG_FILE));
        reader.open();

        uint64_t packetCount{0};
        while (reader.getNextPacket(packet)) {
            ++packetCount;
        }

        reader.close();
    }
    benchmark::DoNotOptimize(packet);
}

static void bmPcapPlusPlusPcapNGZstd(benchmark::State& state) {
    pcpp::RawPacket packet;
    for (auto _ : state) {
        pcpp::PcapNgFileReaderDevice reader(ZSTD(SAMPLE_PCAPNG_FILE));
        reader.open();

        uint64_t packetCount{0};
        while (reader.getNextPacket(packet)) {
            ++packetCount;
        }

        reader.close();
    }
    benchmark::DoNotOptimize(packet);
}

static void bmLibpcapPcap(benchmark::State& state) {
    const std::uint8_t* packet;
    for (auto _ : state) {
        char errBuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcapHandle = pcap_open_offline(QUOTE(SAMPLE_PCAP_FILE), errBuf);

        uint64_t packetCount{0};
        pcap_pkthdr header;
        while ((packet = pcap_next(pcapHandle, &header))) {
            ++packetCount;
        }

        pcap_close(pcapHandle);
    }
    benchmark::DoNotOptimize(packet);
}

static void bmLibpcapPcapNG(benchmark::State& state) {
    const std::uint8_t* packet;
    for (auto _ : state) {
        char errBuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcapHandle = pcap_open_offline(QUOTE(SAMPLE_PCAPNG_FILE), errBuf);

        uint64_t packetCount{0};
        pcap_pkthdr header;
        while ((packet = pcap_next(pcapHandle, &header))) {
            ++packetCount;
        }

        pcap_close(pcapHandle);
    }
    benchmark::DoNotOptimize(packet);
}

BENCHMARK(bmMmprPcap)->Name("mmpr (pcap)");
BENCHMARK(bmMmprPcapNG)->Name("mmpr (pcapng)");
BENCHMARK(bmMmprPcapNGZst)->Name("mmpr (pcapng.zst)");
BENCHMARK(bmPcapPlusPlusPcap)->Name("PcapPlusPlus (pcap)");
BENCHMARK(bmPcapPlusPlusPcapNG)->Name("PcapPlusPlus (pcapng)");
BENCHMARK(bmPcapPlusPlusPcapNGZstd)->Name("PcapPlusPlus (pcapng.zstd)");
BENCHMARK(bmLibpcapPcap)->Name("libpcap (pcap)");
BENCHMARK(bmLibpcapPcapNG)->Name("libpcap (pcapng)");