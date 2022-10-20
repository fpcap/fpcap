#include "gtest/gtest.h"

#include "mmpr/pcapng/PcapNgReader.hpp"

TEST(MMPcapNgReader, ConstructorSimple) {
    mmpr::MMPcapNgReader reader{"tracefiles/pcapng-example.pcapng"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/pcapng-example.pcapng")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(MMPcapNgReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::MMPcapNgReader{"missing-file"}, std::runtime_error);
}

TEST(MMPcapNgReader, FaultyConstructor) {
    EXPECT_THROW(mmpr::MMPcapNgReader{nullptr}, std::logic_error);
    EXPECT_THROW(mmpr::MMPcapNgReader{""}, std::runtime_error);
}