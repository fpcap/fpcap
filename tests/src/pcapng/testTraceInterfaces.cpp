#include <gtest/gtest.h>

#include <fpcap/PacketReader.hpp>
#include <fpcap/pcapng/PcapNgReader.hpp>
#include <iostream>

TEST(TraceInterfaces, AvailableBeforeReadingPackets) {
    // Regression test: getTraceInterfaces() must return the correct interfaces
    // immediately after construction, without reading any packets first.
    // In PcapNG, SHB and IDB blocks always precede packet blocks.
    const auto reader = fpcap::Reader::getReader("tracefiles/many_interfaces-1.pcapng");
    ASSERT_EQ(reader->getTraceInterfaces().size(), 11);
    EXPECT_EQ(*reader->getTraceInterfaces()[0].name, "en0");
}

TEST(TraceInterfaces, AvailableBeforeReadingPacketsPacketReader) {
    // Same test via the PacketReader API
    const fpcap::PacketReader reader{"tracefiles/many_interfaces-1.pcapng"};
    ASSERT_EQ(reader.getTraceInterfaces().size(), 11);
    EXPECT_EQ(*reader.getTraceInterfaces()[0].name, "en0");
}

TEST(TraceInterfaces, ReadBlock) {
    auto reader = fpcap::Reader::getReader("tracefiles/many_interfaces-1.pcapng");

    while (!reader->isExhausted()) {
        reader->readBlock();
    }

    size_t traceInterfaceIndex = 0;
    for (const auto& traceInterface : reader->getTraceInterfaces()) {
        switch (traceInterfaceIndex) {
            ASSERT_TRUE(traceInterface.name) << "interface: " << traceInterfaceIndex;
            ASSERT_FALSE(traceInterface.description)
                << "interface: " << traceInterfaceIndex;
            ASSERT_TRUE(traceInterface.filter) << "interface: " << traceInterfaceIndex;
            ASSERT_TRUE(traceInterface.os) << "interface: " << traceInterfaceIndex;
            ASSERT_EQ(*traceInterface.filter, "host 192.168.1.139")
                << "interface: " << traceInterfaceIndex;
            ASSERT_EQ(*traceInterface.os, "Mac OS X 10.10.4, build 14E46 (Darwin 14.4.0)")
                << "interface: " << traceInterfaceIndex;
        case 0:
            ASSERT_EQ(*traceInterface.name, "en0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 1:
            ASSERT_EQ(*traceInterface.name, "awdl0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 2:
            ASSERT_EQ(*traceInterface.name, "bridge0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 3:
            ASSERT_EQ(*traceInterface.name, "vboxnet0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 4:
            ASSERT_EQ(*traceInterface.name, "utun0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 5:
            ASSERT_EQ(*traceInterface.name, "en1")
                << "interface: " << traceInterfaceIndex;
            break;
        case 6:
            ASSERT_EQ(*traceInterface.name, "vboxnet1")
                << "interface: " << traceInterfaceIndex;
            break;
        case 7:
            ASSERT_EQ(*traceInterface.name, "en2")
                << "interface: " << traceInterfaceIndex;
            break;
        case 8:
            ASSERT_EQ(*traceInterface.name, "p2p0")
                << "interface: " << traceInterfaceIndex;
            break;
        default: ;
        }
        ++traceInterfaceIndex;
    }

    ASSERT_EQ(reader->getTraceInterfaces().size(), 11);
}

TEST(TraceInterfaces, ReadPacket) {
    auto reader = fpcap::Reader::getReader("tracefiles/many_interfaces-1.pcapng");

    fpcap::Packet packet{};
    while (!reader->isExhausted()) {
        if (reader->readNextPacket(packet)) {
            auto interfaceId = packet.interfaceIndex;
            ASSERT_LT(interfaceId, reader->getTraceInterfaces().size());
        }
    }

    ASSERT_EQ(reader->getTraceInterfaces().size(), 11);

    size_t traceInterfaceIndex = 0;
    for (const auto& traceInterface : reader->getTraceInterfaces()) {
        switch (traceInterfaceIndex) {
            ASSERT_TRUE(traceInterface.name) << "interface: " << traceInterfaceIndex;
            ASSERT_FALSE(traceInterface.description)
                << "interface: " << traceInterfaceIndex;
            ASSERT_TRUE(traceInterface.filter) << "interface: " << traceInterfaceIndex;
            ASSERT_TRUE(traceInterface.os) << "interface: " << traceInterfaceIndex;
            ASSERT_EQ(*traceInterface.filter, "host 192.168.1.139")
                << "interface: " << traceInterfaceIndex;
            ASSERT_EQ(*traceInterface.os, "Mac OS X 10.10.4, build 14E46 (Darwin 14.4.0)")
                << "interface: " << traceInterfaceIndex;
        case 0:
            ASSERT_EQ(*traceInterface.name, "en0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 1:
            ASSERT_EQ(*traceInterface.name, "awdl0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 2:
            ASSERT_EQ(*traceInterface.name, "bridge0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 3:
            ASSERT_EQ(*traceInterface.name, "vboxnet0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 4:
            ASSERT_EQ(*traceInterface.name, "utun0")
                << "interface: " << traceInterfaceIndex;
            break;
        case 5:
            ASSERT_EQ(*traceInterface.name, "en1")
                << "interface: " << traceInterfaceIndex;
            break;
        case 6:
            ASSERT_EQ(*traceInterface.name, "vboxnet1")
                << "interface: " << traceInterfaceIndex;
            break;
        case 7:
            ASSERT_EQ(*traceInterface.name, "en2")
                << "interface: " << traceInterfaceIndex;
            break;
        case 8:
            ASSERT_EQ(*traceInterface.name, "p2p0")
                << "interface: " << traceInterfaceIndex;
            break;
        default: ;
        }
        ++traceInterfaceIndex;
    }
}

TEST(TraceInterfaces, TimestampResolution) {
    const auto reader = fpcap::Reader::getReader("tracefiles/many_interfaces-1.pcapng");

    while (!reader->isExhausted()) {
        reader->readBlock();
    }

    ASSERT_EQ(reader->getTraceInterfaces().size(), 11);

    for (const auto& iface : reader->getTraceInterfaces()) {
        // Default is microseconds (10^6) if not specified in IDB
        EXPECT_EQ(iface.timestampResolution, 1000000u);
    }
}
