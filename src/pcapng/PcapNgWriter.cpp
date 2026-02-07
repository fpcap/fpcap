#include "fpcap/pcapng/PcapNgWriter.hpp"

#include <fpcap/Constants.hpp>

#include <filesystem>

namespace fpcap::pcapng {

template <typename TWriter>
PcapNgWriter<TWriter>::PcapNgWriter(const std::string& filepath,
                                    bool append,
                                    const uint16_t linkType)
    : mWriter(filepath, append), mLinkType(linkType) {
    if (not append) {
        writeSectionHeaderBlock();
        writeInterfaceDescriptionBlock();
    } else if (not std::filesystem::exists(filepath)) {
        writeSectionHeaderBlock();
        writeInterfaceDescriptionBlock();
    } else if (std::filesystem::file_size(filepath) == 0) {
        writeSectionHeaderBlock();
        writeInterfaceDescriptionBlock();
    }
}

template <typename TWriter>
void PcapNgWriter<TWriter>::write(const Packet& packet) {
    const uint32_t paddingLen = (4 - packet.captureLength % 4) % 4;
    const uint32_t blockTotalLength = 32 + packet.captureLength + paddingLen;

    const uint64_t timestamp =
        static_cast<uint64_t>(packet.timestampSeconds) * 1'000'000 +
        packet.timestampMicroseconds;
    const uint32_t timestampHigh = static_cast<uint32_t>(timestamp >> 32);
    const uint32_t timestampLow = static_cast<uint32_t>(timestamp & 0xFFFFFFFF);

    constexpr uint32_t blockType = 6;
    constexpr uint32_t interfaceId = 0;

    mWriter.write(reinterpret_cast<const uint8_t*>(&blockType), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&blockTotalLength), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&interfaceId), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&timestampHigh), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&timestampLow), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&packet.captureLength), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&packet.length), 4);
    mWriter.write(packet.data, packet.captureLength);

    if (paddingLen > 0) {
        constexpr uint8_t padding[3] = {0, 0, 0};
        mWriter.write(padding, paddingLen);
    }

    mWriter.write(reinterpret_cast<const uint8_t*>(&blockTotalLength), 4);
}

template <typename TWriter>
void PcapNgWriter<TWriter>::writeSectionHeaderBlock() {
    constexpr uint32_t blockType = PCAPNG;
    constexpr uint32_t blockTotalLength = 28;
    constexpr uint32_t byteOrderMagic = 0x1A2B3C4D;
    constexpr uint16_t majorVersion = 1;
    constexpr uint16_t minorVersion = 0;
    constexpr int64_t sectionLength = -1;

    mWriter.write(reinterpret_cast<const uint8_t*>(&blockType), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&blockTotalLength), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&byteOrderMagic), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&majorVersion), 2);
    mWriter.write(reinterpret_cast<const uint8_t*>(&minorVersion), 2);
    mWriter.write(reinterpret_cast<const uint8_t*>(&sectionLength), 8);
    mWriter.write(reinterpret_cast<const uint8_t*>(&blockTotalLength), 4);
}

template <typename TWriter>
void PcapNgWriter<TWriter>::writeInterfaceDescriptionBlock() {
    constexpr uint32_t blockType = 1;
    constexpr uint32_t blockTotalLength = 20;
    constexpr uint16_t reserved = 0;
    constexpr uint32_t snapLen = 0;

    mWriter.write(reinterpret_cast<const uint8_t*>(&blockType), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&blockTotalLength), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&mLinkType), 2);
    mWriter.write(reinterpret_cast<const uint8_t*>(&reserved), 2);
    mWriter.write(reinterpret_cast<const uint8_t*>(&snapLen), 4);
    mWriter.write(reinterpret_cast<const uint8_t*>(&blockTotalLength), 4);
}

template class PcapNgWriter<StreamFileWriter>;

} // namespace fpcap::pcapng
