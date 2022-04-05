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