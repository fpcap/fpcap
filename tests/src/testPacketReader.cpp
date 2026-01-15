#include <gtest/gtest.h>

#include <fpcap/PacketReader.hpp>

// Constructor tests

TEST(PacketReader, ConstructorSimple) {
    const fpcap::PacketReader reader{"tracefiles/example.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(PacketReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::PacketReader{"missing-file.pcap"}, std::runtime_error);
}

TEST(PacketReader, ConstructorEmptyFilepath) {
    EXPECT_THROW(fpcap::PacketReader{""}, std::runtime_error);
}

TEST(PacketReader, ConstructorMmapFalse) {
    const fpcap::PacketReader reader{"tracefiles/example.pcap", false};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap");
}

// Format auto-detection tests

TEST(PacketReader, DetectPcapFormat) {
    fpcap::PacketReader reader{"tracefiles/example.pcap"};
    fpcap::Packet packet;
    uint64_t count = 0;
    while (!reader.isExhausted()) {
        if (reader.nextPacket(packet)) {
            ASSERT_EQ(packet.dataLinkType, 1); // Ethernet
            ++count;
        }
    }
    ASSERT_EQ(count, 4631);
}

TEST(PacketReader, DetectPcapNgFormat) {
    fpcap::PacketReader reader{"tracefiles/pcapng-example.pcapng"};
    fpcap::Packet packet;
    uint64_t count = 0;
    while (!reader.isExhausted()) {
        if (reader.nextPacket(packet)) {
            ++count;
        }
    }
    ASSERT_EQ(count, 159);
}

TEST(PacketReader, DetectModifiedPcapFormat) {
    fpcap::PacketReader reader{"tracefiles/fritzbox-ip.pcap"};
    fpcap::Packet packet;
    uint64_t count = 0;
    while (!reader.isExhausted()) {
        if (reader.nextPacket(packet)) {
            ASSERT_EQ(packet.dataLinkType, 101); // Raw IP
            ++count;
        }
    }
    ASSERT_EQ(count, 5);
}

#if FPCAP_USE_ZSTD
TEST(PacketReader, DetectZstdCompressedPcap) {
    fpcap::PacketReader reader{"tracefiles/example.pcap.zst"};
    fpcap::Packet packet;
    uint64_t count = 0;
    while (!reader.isExhausted()) {
        if (reader.nextPacket(packet)) {
            ASSERT_EQ(packet.dataLinkType, 1);
            ++count;
        }
    }
    ASSERT_EQ(count, 4631);
}

TEST(PacketReader, DetectZstdCompressedPcapNg) {
    fpcap::PacketReader reader{"tracefiles/pcapng-example.pcapng.zst"};
    fpcap::Packet packet;
    uint64_t count = 0;
    while (!reader.isExhausted()) {
        if (reader.nextPacket(packet)) {
            ++count;
        }
    }
    ASSERT_EQ(count, 159);
}
#endif

// nextPacket() overloads

TEST(PacketReader, NextPacketByValue) {
    fpcap::PacketReader reader{"tracefiles/fritzbox-ip.pcap"};
    const auto packet = reader.nextPacket();
    EXPECT_GT(packet.captureLength, 0u);
    EXPECT_NE(packet.data, nullptr);
}

TEST(PacketReader, NextPacketByReference) {
    fpcap::PacketReader reader{"tracefiles/fritzbox-ip.pcap"};
    fpcap::Packet packet;
    const bool result = reader.nextPacket(packet);
    EXPECT_TRUE(result);
    EXPECT_GT(packet.captureLength, 0u);
    EXPECT_NE(packet.data, nullptr);
}

// Metadata tests - PCAP format throws exceptions for metadata methods

TEST(PacketReader, GetMetadataPcapThrows) {
    fpcap::PacketReader reader{"tracefiles/example.pcap"};
    // PCAP format doesn't support metadata, throws exceptions
    EXPECT_THROW(reader.getComment(), std::runtime_error);
    EXPECT_THROW(reader.getOS(), std::runtime_error);
    EXPECT_THROW(reader.getHardware(), std::runtime_error);
    EXPECT_THROW(reader.getUserApplication(), std::runtime_error);
}

TEST(PacketReader, GetTraceInterfacesPcapNg) {
    fpcap::PacketReader reader{"tracefiles/many_interfaces-1.pcapng"};
    // Must read packets first to populate interfaces
    fpcap::Packet packet;
    while (!reader.isExhausted()) {
        reader.nextPacket(packet);
    }
    const auto interfaces = reader.getTraceInterfaces();
    ASSERT_EQ(interfaces.size(), 11);
}

TEST(PacketReader, GetTraceInterfaceById) {
    fpcap::PacketReader reader{"tracefiles/many_interfaces-1.pcapng"};
    // Must read packets first to populate interfaces
    fpcap::Packet packet;
    while (!reader.isExhausted()) {
        reader.nextPacket(packet);
    }
    const auto iface = reader.getTraceInterface(0);
    // Interface 0 should exist and have a valid data link type
    EXPECT_GE(iface.dataLinkType, 0);
}

TEST(PacketReader, GetTraceInterfacesPcap) {
    fpcap::PacketReader reader{"tracefiles/example.pcap"};
    // Read all packets first
    fpcap::Packet packet;
    while (!reader.isExhausted()) {
        reader.nextPacket(packet);
    }
    const auto interfaces = reader.getTraceInterfaces();
    // PCAP format doesn't provide interface metadata (returns empty)
    EXPECT_TRUE(interfaces.empty());
}
