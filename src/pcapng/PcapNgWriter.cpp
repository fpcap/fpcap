#include "fpcap/pcapng/PcapNgWriter.hpp"

namespace fpcap {

template <typename TWriter>
PcapNgWriter<TWriter>::PcapNgWriter(const std::string& filepath) : mWriter(filepath) {}

template <typename TWriter>
void PcapNgWriter<TWriter>::write(const Packet& packet) {
    writePacket(packet, 0);
}

template <typename TWriter>
void PcapNgWriter<TWriter>::writePacket(const Packet& packet, uint32_t interfaceId) {
    pcapng::EnhancedPacketBlock epb;
    epb.blockTotalLength = 32u + packet.captureLength + (4u - packet.captureLength % 4u);
    epb.interfaceId = interfaceId;

    // TODO improve, seems we are losing precious here, cf. util::calculateTimestamps
    const uint64_t timestamp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(packet.timestampSeconds) +
            std::chrono::microseconds(packet.timestampMicroseconds))
            .count();
    epb.timestampHigh = (timestamp >> 32) & 0xFFFFFFFF;
    epb.timestampLow = timestamp & 0xFFFFFFFF;

    epb.capturePacketLength = packet.captureLength;
    epb.originalPacketLength = packet.length;
    epb.packetData = packet.data;

    writeEPB(epb);
}

template <typename TWriter>
void PcapNgWriter<TWriter>::writeSHB(const pcapng::SectionHeaderBlock& shb) {
    // without options the SHB is 28 bytes long
    uint32_t blockTotalLength = 28u;
    constexpr uint32_t zeroPadding = 0u;

    // calculate options length
    if (!shb.options.comment.empty()) {
        blockTotalLength +=
            4u + shb.options.comment.length() + (4u - shb.options.comment.length() % 4u);
    }
    if (!shb.options.os.empty()) {
        blockTotalLength +=
            4u + shb.options.os.length() + (4u - shb.options.os.length() % 4u);
    }
    if (!shb.options.hardware.empty()) {
        blockTotalLength += 4u + shb.options.hardware.length() +
                            (4u - shb.options.hardware.length() % 4u);
    }
    if (!shb.options.userApplication.empty()) {
        blockTotalLength += 4u + shb.options.userApplication.length() +
                            (4u - shb.options.userApplication.length() % 4u);
    }
    if (blockTotalLength > 28u) {
        // add 4 bytes for opt_endofopt and padding of there were options
        blockTotalLength += 4u;
    }

    mWriter.write(static_cast<uint32_t>(FPCAP_SECTION_HEADER_BLOCK));
    mWriter.write(blockTotalLength);
    mWriter.write(static_cast<uint32_t>(0x1A2B3C4D));
    mWriter.write(static_cast<uint16_t>(1u));
    mWriter.write(static_cast<uint16_t>(0u));
    mWriter.write(static_cast<int64_t>(-1));

    // write options
    if (!shb.options.comment.empty()) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_COMMENT));
        if (shb.options.comment.length() >= 65535u) {
            throw std::runtime_error("Value for SHB comment option exceeds 16-bit size");
        }
        mWriter.write(static_cast<uint16_t>(shb.options.comment.length()));
        mWriter.write(reinterpret_cast<const uint8_t*>(shb.options.comment.c_str()),
                      shb.options.comment.length());

        auto padding = 4u - shb.options.comment.length() % 4u;
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);
    }

    if (!shb.options.os.empty()) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_SHB_OS));
        if (shb.options.os.length() >= 65535u) {
            throw std::runtime_error("Value for SHB OS option exceeds 16-bit size");
        }
        mWriter.write(static_cast<uint16_t>(shb.options.os.length()));
        mWriter.write(reinterpret_cast<const uint8_t*>(shb.options.os.c_str()),
                      shb.options.os.length());

        auto padding = 4u - shb.options.os.length() % 4u;
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);
    }

    if (!shb.options.hardware.empty()) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_SHB_HARDWARE));
        if (shb.options.hardware.length() >= 65535u) {
            throw std::runtime_error("Value for SHB hardware option exceeds 16-bit size");
        }
        mWriter.write(static_cast<uint16_t>(shb.options.hardware.length()));
        mWriter.write(reinterpret_cast<const uint8_t*>(shb.options.hardware.c_str()),
                      shb.options.hardware.length());

        auto padding = 4u - shb.options.hardware.length() % 4u;
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);
    }

    if (!shb.options.userApplication.empty()) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_SHB_USERAPPL));
        if (shb.options.userApplication.length() >= 65535u) {
            throw std::runtime_error("Value for SHB user app option exceeds 16-bit size");
        }
        mWriter.write(static_cast<uint16_t>(shb.options.userApplication.length()));
        mWriter.write(
            reinterpret_cast<const uint8_t*>(shb.options.userApplication.c_str()),
            shb.options.userApplication.length());

        auto padding = 4u - shb.options.userApplication.length() % 4u;
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);
    }

    // write opt_endofopt and padding at end of options (if there were any)
    if (blockTotalLength > 28) {
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), 4);
    }

    mWriter.write(blockTotalLength);
}

template <typename TWriter>
void PcapNgWriter<TWriter>::writeIDB(const pcapng::InterfaceDescriptionBlock& idb) {
    // without options the IDB is 20 bytes long
    uint32_t blockTotalLength = 20u;
    constexpr uint32_t zeroPadding = 0u;

    if (idb.options.timestampResolution != 0) {
        blockTotalLength += 8u;
    }
    if (idb.options.name.has_value()) {
        blockTotalLength +=
            4u + idb.options.name->length() + (4u - idb.options.name->length() % 4u);
    }
    if (idb.options.description.has_value()) {
        blockTotalLength += 4u + idb.options.description->length() +
                            (4u - idb.options.description->length() % 4u);
    }
    if (idb.options.filter.has_value()) {
        blockTotalLength +=
            4u + idb.options.filter->length() + (4u - idb.options.filter->length() % 4u);
    }
    if (idb.options.os.has_value()) {
        blockTotalLength +=
            4u + idb.options.os->length() + (4u - idb.options.os->length() % 4u);
    }
    if (blockTotalLength > 20u) {
        // add 4 bytes for opt_endofopt and padding of there were options
        blockTotalLength += 4u;
    }

    mWriter.write(static_cast<uint32_t>(FPCAP_INTERFACE_DESCRIPTION_BLOCK));
    mWriter.write(blockTotalLength);
    mWriter.write(idb.linkType);
    mWriter.write(static_cast<uint16_t>(0u)); // reserved field
    mWriter.write(idb.snapLen);

    // write IDB options
    if (idb.options.timestampResolution != 0) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_IDB_TSRESOL));
        mWriter.write(static_cast<uint16_t>(1u));
        mWriter.write(static_cast<uint8_t>(0x06)); // 10^-6 -> nanoseconds
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), 3);
    }
    if (idb.options.name.has_value()) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_IDB_NAME));
        if (idb.options.name->length() >= 65535u) {
            throw std::runtime_error("Value for IDB name option exceeds 16-bit size");
        }
        mWriter.write(static_cast<uint16_t>(idb.options.name->length()));
        mWriter.write(reinterpret_cast<const uint8_t*>(idb.options.name->c_str()),
                      idb.options.name->length());

        auto padding = 4u - idb.options.name->length() % 4u;
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);
    }
    if (idb.options.description.has_value()) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_IDB_DESCRIPTION));
        if (idb.options.description->length() >= 65535u) {
            throw std::runtime_error(
                "Value for IDB description option exceeds 16-bit size");
        }
        mWriter.write(static_cast<uint16_t>(idb.options.description->length()));
        mWriter.write(reinterpret_cast<const uint8_t*>(idb.options.description->c_str()),
                      idb.options.description->length());

        auto padding = 4u - idb.options.description->length() % 4u;
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);
    }
    if (idb.options.filter.has_value()) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_IDB_FILTER));
        if (idb.options.filter->length() >= 65535u) {
            throw std::runtime_error("Value for IDB filter option exceeds 16-bit size");
        }
        mWriter.write(static_cast<uint16_t>(idb.options.filter->length()));
        mWriter.write(reinterpret_cast<const uint8_t*>(idb.options.filter->c_str()),
                      idb.options.filter->length());

        auto padding = 4u - idb.options.filter->length() % 4u;
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);
    }
    if (idb.options.os.has_value()) {
        mWriter.write(static_cast<uint16_t>(FPCAP_BLOCK_OPTION_IDB_OS));
        if (idb.options.os->length() >= 65535u) {
            throw std::runtime_error("Value for IDB OS option exceeds 16-bit size");
        }
        mWriter.write(static_cast<uint16_t>(idb.options.os->length()));
        mWriter.write(reinterpret_cast<const uint8_t*>(idb.options.os->c_str()),
                      idb.options.os->length());

        auto padding = 4u - idb.options.os->length() % 4u;
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);
    }

    // write opt_endofopt and padding at end of options (if there were any)
    if (blockTotalLength > 20u) {
        mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), 4u);
    }

    mWriter.write(blockTotalLength);
}

template <typename TWriter>
void PcapNgWriter<TWriter>::writeEPB(const pcapng::EnhancedPacketBlock& epb) {
    // calculate padding since packet data is aligned to 32 bits
    auto padding = 4u - epb.capturePacketLength % 4u;

    mWriter.write(static_cast<uint32_t>(FPCAP_ENHANCED_PACKET_BLOCK));
    mWriter.write(epb.blockTotalLength);
    mWriter.write(epb.interfaceId);
    mWriter.write(epb.timestampHigh);
    mWriter.write(epb.timestampLow);
    mWriter.write(epb.capturePacketLength);
    mWriter.write(epb.originalPacketLength);
    mWriter.write(epb.packetData, epb.capturePacketLength);

    // write padding for packet data
    constexpr uint32_t zeroPadding = 0u;
    mWriter.write(reinterpret_cast<const uint8_t*>(&zeroPadding), padding);

    mWriter.write(epb.blockTotalLength);

    // TODO write options
}

template class PcapNgWriter<StreamFileWriter>;

} // namespace fpcap
