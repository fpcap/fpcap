#include <gtest/gtest.h>

#include "BlockTestUtil.hpp"

#include <fpcap/pcapng/PcapNgBlockParser.hpp>
#include <fpcap/pcapng/PcapNgBlockType.hpp>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

using fpcap::test::ExactBlock;
using fpcap::test::optionHeader;

namespace {

struct RawOption {
    uint16_t type;
    std::vector<uint8_t> value;
};

std::vector<uint8_t> u64(const uint64_t value) {
    std::vector<uint8_t> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    return bytes;
}

void append(std::vector<uint8_t>& out, const void* data, const size_t length) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    out.insert(out.end(), bytes, bytes + length);
}

std::vector<uint8_t> createInterfaceStatisticsBlock(const uint32_t timestampHigh,
                                                    const uint32_t timestampLow,
                                                    const std::vector<RawOption>& options) {
    std::vector<uint8_t> body;
    const uint32_t interfaceId = 0;
    append(body, &interfaceId, 4);
    append(body, &timestampHigh, 4);
    append(body, &timestampLow, 4);
    for (const auto& [type, value] : options) {
        const auto length = static_cast<uint16_t>(value.size());
        append(body, &type, 2);
        append(body, &length, 2);
        append(body, value.data(), value.size());
        body.resize(body.size() + (4 - value.size() % 4) % 4, 0);
    }
    if (!options.empty()) {
        body.resize(body.size() + 4, 0); // opt_endofopt
    }

    const uint32_t blockType = fpcap::pcapng::INTERFACE_STATISTICS_BLOCK;
    const auto blockTotalLength = static_cast<uint32_t>(12 + body.size());
    std::vector<uint8_t> block;
    append(block, &blockType, 4);
    append(block, &blockTotalLength, 4);
    append(block, body.data(), body.size());
    append(block, &blockTotalLength, 4);
    return block;
}

} // namespace

TEST(InterfaceStatisticsBlock, ParsesCounterOptions) {
    // non-zero timestamp low catches options being read from the wrong offset
    const auto block = createInterfaceStatisticsBlock(0x00061234, 0x89ABCDEF,
                                                      {{4, u64(100)},
                                                       {5, u64(1)},
                                                       {6, u64(90)},
                                                       {7, u64(2)},
                                                       {8, u64(88)}});

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(block.data(), isb);

    EXPECT_EQ(isb.blockTotalLength, block.size());
    EXPECT_EQ(isb.timestampHigh, 0x00061234u);
    EXPECT_EQ(isb.timestampLow, 0x89ABCDEFu);
    EXPECT_EQ(isb.options.receivedPackets, 100u);
    EXPECT_EQ(isb.options.interfaceDroppedPackets, 1u);
    EXPECT_EQ(isb.options.filterAcceptedPackets, 90u);
    EXPECT_EQ(isb.options.osDroppedPackets, 2u);
    EXPECT_EQ(isb.options.deliveredPackets, 88u);
}

TEST(InterfaceStatisticsBlock, SkipsPaddedOptionsBeforeCounters) {
    // comment with length 5 is padded to 8 bytes
    const std::vector<uint8_t> comment = {'h', 'e', 'l', 'l', 'o'};
    const auto block =
        createInterfaceStatisticsBlock(1, 2, {{1, comment}, {4, u64(42)}});

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(block.data(), isb);

    EXPECT_EQ(isb.options.receivedPackets, 42u);
    EXPECT_FALSE(isb.options.interfaceDroppedPackets.has_value());
}

TEST(InterfaceStatisticsBlock, NoOptions) {
    // timestamp low reads as option type 4 with length 8 if misinterpreted as an option
    const auto block = createInterfaceStatisticsBlock(0, 0x00080004, {});
    ASSERT_EQ(block.size(), 24u);

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(block.data(), isb);

    EXPECT_EQ(isb.timestampLow, 0x00080004u);
    EXPECT_FALSE(isb.options.receivedPackets.has_value());
}

TEST(InterfaceStatisticsBlock, IgnoresCounterWithWrongLength) {
    const auto block = createInterfaceStatisticsBlock(0, 0, {{4, {1, 2, 3, 4}}});

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(block.data(), isb);

    EXPECT_FALSE(isb.options.receivedPackets.has_value());
}

TEST(InterfaceStatisticsBlock, IgnoresCounterHeaderInLastOptionBytes) {
    const ExactBlock block({5, 28, 0, 0, 0, optionHeader(4, 8), 28});

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(block.get(), isb);

    EXPECT_FALSE(isb.options.receivedPackets.has_value());
}

TEST(InterfaceStatisticsBlock, IgnoresCounterRunningIntoTrailer) {
    const ExactBlock block({5, 32, 0, 0, 0, optionHeader(4, 8), 0xAAAAAAAA, 32});

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(block.get(), isb);

    EXPECT_FALSE(isb.options.receivedPackets.has_value());
}

TEST(InterfaceStatisticsBlock, IgnoresZeroLengthCounterAtEnd) {
    const ExactBlock block({5, 28, 0, 0, 0, optionHeader(4, 0), 28});

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(block.get(), isb);

    EXPECT_FALSE(isb.options.receivedPackets.has_value());
}

TEST(InterfaceStatisticsBlock, ReusedBlockDoesNotKeepOldCounters) {
    const ExactBlock first(
        {5, 40, 0, 0, 0, optionHeader(7, 8), 42, 0, optionHeader(0, 0), 40});
    const ExactBlock second({5, 28, 0, 0, 0, optionHeader(0, 0), 28});

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(first.get(), isb);
    ASSERT_EQ(isb.options.osDroppedPackets, 42u);
    fpcap::pcapng::PcapNgBlockParser::readISB(second.get(), isb);

    EXPECT_FALSE(isb.options.osDroppedPackets.has_value());
}

TEST(InterfaceStatisticsBlock, ParsesDumpcapBlockFromTraceFile) {
    std::ifstream file("tracefiles/pcapng-example.pcapng", std::ios::binary);
    ASSERT_TRUE(file.is_open());
    const std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), {});
    constexpr size_t isbOffset = 10624;
    ASSERT_GT(data.size(), isbOffset + 108);

    fpcap::pcapng::InterfaceStatisticsBlock isb{};
    fpcap::pcapng::PcapNgBlockParser::readISB(&data[isbOffset], isb);

    EXPECT_EQ(isb.blockTotalLength, 108u);
    EXPECT_EQ(isb.options.receivedPackets, 59u);
    EXPECT_EQ(isb.options.interfaceDroppedPackets, 0u);
    EXPECT_FALSE(isb.options.osDroppedPackets.has_value());
}
