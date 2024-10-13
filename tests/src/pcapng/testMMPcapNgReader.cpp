#include <gtest/gtest.h>

#include <fpcap/pcapng/PcapNgReader.hpp>

TEST(MMPcapNgReader, ConstructorSimple) {
    const fpcap::pcapng::MMPcapNgReader reader{"tracefiles/pcapng-example.pcapng"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/pcapng-example.pcapng")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(MMPcapNgReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::pcapng::MMPcapNgReader{"missing-file"}, std::runtime_error);
}

TEST(MMPcapNgReader, FaultyConstructor) {
#ifdef __linux__ // throws un-catchable SEH exception on Windows
    EXPECT_THROW(fpcap::pcapng::MMPcapNgReader{nullptr}, std::logic_error);
#endif
    EXPECT_THROW(fpcap::pcapng::MMPcapNgReader{""}, std::runtime_error);
}
