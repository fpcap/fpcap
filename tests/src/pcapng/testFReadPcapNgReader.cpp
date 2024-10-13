#include <gtest/gtest.h>

#include <fpcap/pcapng/PcapNgReader.hpp>

TEST(FReadPcapNgReader, ConstructorSimple) {
    const fpcap::pcapng::FReadPcapNgReader reader{"tracefiles/pcapng-example.pcapng"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/pcapng-example.pcapng")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(FReadPcapNgReader, ConstructorMissingFile) {
    EXPECT_THROW(fpcap::pcapng::FReadPcapNgReader{"missing-file"}, std::runtime_error);
}

#if __linux__
// TODO this behaves strangely on Windows
TEST(FReadPcapNgReader, FaultyConstructorNullptr) {
    EXPECT_THROW(fpcap::pcapng::FReadPcapNgReader{nullptr}, std::logic_error);
}
#endif

TEST(FReadPcapNgReader, FaultyConstructorEmptyFilepath) {
    EXPECT_THROW(fpcap::pcapng::FReadPcapNgReader{""}, std::runtime_error);
}
