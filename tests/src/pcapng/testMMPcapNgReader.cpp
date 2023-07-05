#include "gtest/gtest.h"

#include "fpcap/pcapng/PcapNgReader.hpp"

TEST(MMPcapNgReader, ConstructorSimple) {
    fpcap::MMPcapNgReader reader{"tracefiles/pcapng-example.pcapng"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/pcapng-example.pcapng")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(MMPcapNgReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::MMPcapNgReader{"missing-file"}, std::runtime_error);
}

TEST(MMPcapNgReader, FaultyConstructor) {
#ifdef __linux__ // throws un-catchable SEH exception on Windows
    EXPECT_THROW(fpcap::MMPcapNgReader{nullptr}, std::logic_error);
#endif
    EXPECT_THROW(fpcap::MMPcapNgReader{""}, std::runtime_error);
}
