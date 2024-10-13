#include <gtest/gtest.h>

#include <fpcap/modified_pcap/ModifiedPcapReader.hpp>

TEST(MMModifiedPcapReader, ConstructorSimple) {
    const fpcap::modified_pcap::MMModifiedPcapReader reader
        {"tracefiles/fritzbox-ip.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/fritzbox-ip.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(MMModifiedPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::modified_pcap::MMModifiedPcapReader{"missing-file"},
                 std::runtime_error);
}

TEST(MMModifiedPcapReader, FaultyConstructor) {
#ifdef __linux__ // throws un-catchable SEH exception on Windows
    EXPECT_THROW(fpcap::modified_pcap::MMModifiedPcapReader{nullptr}, std::logic_error);
#endif
    EXPECT_THROW(fpcap::modified_pcap::MMModifiedPcapReader{""}, std::runtime_error);
}

TEST(MMModifiedPcapReader, DLT) {
    {
        // Standard Ethernet
        fpcap::modified_pcap::MMModifiedPcapReader reader{"tracefiles/fritzbox-ip.pcap"};
        fpcap::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(packet.dataLinkType, 101 /* Raw IP */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 5);
    }
}
