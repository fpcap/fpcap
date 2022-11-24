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
#ifdef __linux__ // throws un-catchable SEH exception on Windows
    EXPECT_THROW(mmpr::MMPcapNgReader{nullptr}, std::logic_error);
#endif
    EXPECT_THROW(mmpr::MMPcapNgReader{""}, std::runtime_error);
}
