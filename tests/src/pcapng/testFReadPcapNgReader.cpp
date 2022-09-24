#include "gtest/gtest.h"

#include "mmpr/pcapng/FReadPcapNgReader.h"

TEST(FReadPcapNgReader, ConstructorSimple) {
    mmpr::FReadPcapNgReader reader{"tracefiles/pcapng-example.pcapng"};
    EXPECT_EQ(reader.getFilepath(), "tracefiles/pcapng-example.pcapng")
        << "Hint: make sure to execute unit tests from root directory";
}

TEST(FReadPcapNgReader, ConstructorMissingFile) {
    EXPECT_THROW(mmpr::FReadPcapNgReader{"missing-file"}, std::runtime_error);
}

TEST(FReadPcapNgReader, FaultyConstructor) {
    EXPECT_THROW(mmpr::FReadPcapNgReader{nullptr}, std::logic_error);
    EXPECT_THROW(mmpr::FReadPcapNgReader{""}, std::runtime_error);
}