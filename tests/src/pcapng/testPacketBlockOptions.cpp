#include <gtest/gtest.h>

#include "BlockTestUtil.hpp"

#include <fpcap/pcapng/PcapNgBlockOption.hpp>
#include <fpcap/pcapng/PcapNgBlockParser.hpp>
#include <fpcap/pcapng/PcapNgBlockType.hpp>

using fpcap::pcapng::EPB_DROPCOUNT;
using fpcap::pcapng::EPB_FLAGS;
using fpcap::pcapng::EPB_PACKETID;
using fpcap::test::ExactBlock;
using fpcap::test::optionHeader;

namespace {
constexpr uint32_t epbType = fpcap::pcapng::ENHANCED_PACKET_BLOCK;
constexpr uint32_t pbType = fpcap::pcapng::PACKET_BLOCK;
} // namespace

TEST(PacketBlockOptions, EpbOptionsStartAfterPaddedPacketData) {
    // 5 byte packet padded to 8, so options start at 28 + 8
    const ExactBlock block({epbType, 48, 0, 0, 0, 5, 5, 0x44332211, 0x55,
                            optionHeader(EPB_FLAGS, 4), 1, 48});

    fpcap::pcapng::EnhancedPacketBlock epb{};
    fpcap::pcapng::PcapNgBlockParser::readEPB(block.get(), epb);

    EXPECT_EQ(epb.capturePacketLength, 5u);
    EXPECT_EQ(epb.packetData[0], 0x11);
    EXPECT_EQ(epb.packetData[4], 0x55);
    EXPECT_EQ(epb.options, block.get() + 36);
    EXPECT_EQ(epb.optionsLength, 8u);
}

TEST(PacketBlockOptions, PbOptionsStartAfterPaddedPacketData) {
    const ExactBlock block(
        {pbType, 48, 0, 0, 0, 5, 5, 0x44332211, 0x55, optionHeader(EPB_FLAGS, 4), 1, 48});

    fpcap::pcapng::PacketBlock pb{};
    fpcap::pcapng::PcapNgBlockParser::readPB(block.get(), pb);

    EXPECT_EQ(pb.capturePacketLength, 5u);
    EXPECT_EQ(pb.packetData[4], 0x55);
    EXPECT_EQ(pb.options, block.get() + 36);
    EXPECT_EQ(pb.optionsLength, 8u);
}

TEST(PacketBlockOptions, EpbWithSeveralOptions) {
    // comment of length 5 padded to 8, flags, opt_endofopt
    const ExactBlock block({epbType, 60, 0, 0, 0, 4, 4, 0x44332211, optionHeader(1, 5),
                            0x6C6C6568, 0x6F, optionHeader(EPB_FLAGS, 4), 1,
                            optionHeader(0, 0), 60});

    fpcap::pcapng::EnhancedPacketBlock epb{};
    fpcap::pcapng::PcapNgBlockParser::readEPB(block.get(), epb);

    EXPECT_EQ(epb.options, block.get() + 32);
    EXPECT_EQ(epb.optionsLength, 24u);
}

TEST(PacketBlockOptions, EpbWithoutOptions) {
    const ExactBlock block({epbType, 36, 0, 0, 0, 4, 4, 0x44332211, 36});

    fpcap::pcapng::EnhancedPacketBlock epb{};
    fpcap::pcapng::PcapNgBlockParser::readEPB(block.get(), epb);

    EXPECT_EQ(epb.options, nullptr);
    EXPECT_EQ(epb.optionsLength, 0u);
}

TEST(PacketBlockOptions, EpbShorterThanMinimumSize) {
    // block total length below the 32 byte minimum must not wrap around
    const ExactBlock block({epbType, 28, 0, 0, 0, 0, 28});

    fpcap::pcapng::EnhancedPacketBlock epb{};
    fpcap::pcapng::PcapNgBlockParser::readEPB(block.get(), epb);

    EXPECT_EQ(epb.blockTotalLength, 28u);
    EXPECT_EQ(epb.options, nullptr);
    EXPECT_EQ(epb.optionsLength, 0u);
}

TEST(PacketBlockOptions, PbShorterThanMinimumSize) {
    const ExactBlock block({pbType, 28, 0, 0, 0, 0, 28});

    fpcap::pcapng::PacketBlock pb{};
    fpcap::pcapng::PcapNgBlockParser::readPB(block.get(), pb);

    EXPECT_EQ(pb.options, nullptr);
    EXPECT_EQ(pb.optionsLength, 0u);
}

TEST(PacketBlockOptions, EpbCapturedLengthLargerThanBlock) {
    // a 32-bit options offset would wrap around to 24
    const ExactBlock block({epbType, 36, 0, 0, 0, 0xFFFFFFFC, 4, 0x44332211, 36});

    fpcap::pcapng::EnhancedPacketBlock epb{};
    fpcap::pcapng::PcapNgBlockParser::readEPB(block.get(), epb);

    EXPECT_EQ(epb.options, nullptr);
    EXPECT_EQ(epb.optionsLength, 0u);
}

// The option values below are only read when FPCAP_DEBUG_LOGGING is on, so these two
// catch over-reads only in an ASan build with logging enabled.
TEST(PacketBlockOptions, EpbIgnoresOptionRunningPastBlock) {
    const ExactBlock block(
        {epbType, 40, 0, 0, 0, 4, 4, 0x44332211, optionHeader(EPB_PACKETID, 8), 40});

    fpcap::pcapng::EnhancedPacketBlock epb{};
    fpcap::pcapng::PcapNgBlockParser::readEPB(block.get(), epb);

    EXPECT_EQ(epb.optionsLength, 4u);
}

TEST(PacketBlockOptions, EpbIgnoresZeroLengthDropCountAtEnd) {
    const ExactBlock block(
        {epbType, 40, 0, 0, 0, 4, 4, 0x44332211, optionHeader(EPB_DROPCOUNT, 0), 40});

    fpcap::pcapng::EnhancedPacketBlock epb{};
    fpcap::pcapng::PcapNgBlockParser::readEPB(block.get(), epb);

    EXPECT_EQ(epb.optionsLength, 4u);
}
