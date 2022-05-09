#include <gtest/gtest.h>

#include <mmpr/pcap/MMPcapReader.h>

TEST(MMPcapReader, ConstructorSimple) {
    mmpr::MMPcapReader reader{"tracefiles/example.pcap"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/example.pcap")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(MMPcapReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::MMPcapReader{"missing-file"}, std::runtime_error);
}

TEST(MMPcapReader, FaultyConstructor) {
    EXPECT_THROW(mmpr::MMPcapReader{nullptr}, std::logic_error);
    EXPECT_THROW(mmpr::MMPcapReader{""}, std::runtime_error);
}

TEST(MMPcapReader, DLT) {
    {
        // Standard Ethernet
        mmpr::MMPcapReader reader{"tracefiles/example.pcap"};
        reader.open();
        mmpr::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(reader.getDataLinkType(), 1 /* Ethernet (10Mb) */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 4631);
    }
    {
        // Linux Cooked Capture (SLL)
        mmpr::MMPcapReader reader{"tracefiles/linux-cooked-unsw-nb15.pcap"};
        reader.open();
        mmpr::Packet packet;
        uint64_t processedPackets{0};
        while (!reader.isExhausted()) {
            if (reader.readNextPacket(packet)) {
                ASSERT_EQ(reader.getDataLinkType(), 113 /* Linux Cooked */);
                ++processedPackets;
            }
        }
        ASSERT_EQ(processedPackets, 1000);
    }

}