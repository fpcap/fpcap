#include <gtest/gtest.h>

#include <fpcap/pcap/PcapReader.hpp>

TEST(MMPcapReader, ConstructorSimple) {
    const fpcap::pcap::MMPcapReader reader{"tracefiles/example.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(MMPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::pcap::MMPcapReader{"missing-file"}, std::runtime_error);
}

TEST(MMPcapReader, FaultyConstructor) {
#ifdef __linux__ // throws un-catchable SEH exception on Windows
    EXPECT_THROW(fpcap::pcap::MMPcapReader{nullptr}, std::logic_error);
#endif
    EXPECT_THROW(fpcap::pcap::MMPcapReader{""}, std::runtime_error);
}

TEST(MMPcapReader, DLT) {
    {
        // Standard Ethernet
        fpcap::pcap::MMPcapReader reader{"tracefiles/example.pcap"};
        fpcap::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(packet.dataLinkType, 1 /* Ethernet (10Mb) */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 4631);
    }
    {
        // Linux Cooked Capture (SLL)
        fpcap::pcap::MMPcapReader reader{"tracefiles/linux-cooked-unsw-nb15.pcap"};
        fpcap::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(packet.dataLinkType, 113 /* Linux Cooked */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 1000);
    }
}
