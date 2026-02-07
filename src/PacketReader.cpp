#include "fpcap/PacketReader.hpp"

#include <fpcap/util.hpp>
#include <fpcap/Constants.hpp>

#include <filesystem>

using namespace std;
using namespace fpcap;

PacketReader::PacketReader(const std::string& filepath, const bool mmap)
    : mFilepath(filepath) {
    if (filepath.empty()) {
        throw runtime_error("empty filepath");
    }

    if (not filesystem::exists(filepath)) {
        throw runtime_error(
            "file not found" + std::filesystem::absolute(mFilepath).string());
    }

    const auto fileMagic = util::read32bitsFromFile(filepath);
    if (not fileMagic.has_value()) {
        throw runtime_error("could not determine file type on first 32 bits");
    }

    switch (fileMagic.value()) {
    case PCAP_MICROSECONDS:
    case PCAP_NANOSECONDS: {
        if (mmap) {
            mFileReader.emplace<pcap::MMPcapReader>(filepath);
        } else {
            mFileReader.emplace<pcap::FReadPcapReader>(filepath);
        }
        break;
    }
    case PCAPNG: {
        if (mmap) {
            mFileReader.emplace<pcapng::MMPcapNgReader>(filepath);
        } else {
            mFileReader.emplace<pcapng::FReadPcapNgReader>(filepath);
        }
        break;
    }
    case MODIFIED_PCAP: {
        if (mmap) {
            mFileReader.emplace<modified_pcap::MMModifiedPcapReader>(filepath);
        } else {
            mFileReader.emplace<modified_pcap::FReadModifiedPcapReader>(filepath);
        }
        break;
    }
    case ZSTD: {
        ZstdFileReader compressedFileReader(filepath);
        switch (*reinterpret_cast<const uint32_t*>(compressedFileReader.data())) {
        case PCAP_MICROSECONDS:
        case PCAP_NANOSECONDS: {
            mFileReader.emplace<pcap::ZstdPcapReader>(std::move(compressedFileReader));
            break;
        }
        case PCAPNG: {
            mFileReader.emplace<
                pcapng::ZstdPcapNgReader>(std::move(compressedFileReader));
            break;
        }
        case MODIFIED_PCAP: {
            mFileReader.emplace<modified_pcap::ZstdModifiedPcapReader>(
                std::move(compressedFileReader));
            break;
        }
        default:
            throw runtime_error("failed to determine file type after decompression");
        }
        break;
    }
    default:
        throw runtime_error("unsupported file type");
    }
}

Packet PacketReader::nextPacket() {
    Packet packet;
    nextPacket(packet);
    return packet;
}

bool PacketReader::nextPacket(Packet& packet) {
    if (std::holds_alternative<pcap::MMPcapReader>(mFileReader)) {
        return std::get<pcap::MMPcapReader>(mFileReader).readNextPacket(packet);
    }
    if (std::holds_alternative<pcap::FReadPcapReader>(mFileReader)) {
        return std::get<pcap::FReadPcapReader>(mFileReader).readNextPacket(packet);
    }
    if (std::holds_alternative<pcapng::MMPcapNgReader>(mFileReader)) {
        return std::get<pcapng::MMPcapNgReader>(mFileReader).readNextPacket(packet);
    }
    if (std::holds_alternative<pcapng::FReadPcapNgReader>(mFileReader)) {
        return std::get<pcapng::FReadPcapNgReader>(mFileReader).readNextPacket(packet);
    }
    if (std::holds_alternative<modified_pcap::MMModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::MMModifiedPcapReader>(mFileReader).
            readNextPacket(packet);
    }
    if (std::holds_alternative<modified_pcap::FReadModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::FReadModifiedPcapReader>(mFileReader).
            readNextPacket(packet);
    }
    if (std::holds_alternative<pcap::ZstdPcapReader>(mFileReader)) {
        return std::get<pcap::ZstdPcapReader>(mFileReader).readNextPacket(packet);
    }
    if (std::holds_alternative<pcapng::ZstdPcapNgReader>(mFileReader)) {
        return std::get<pcapng::ZstdPcapNgReader>(mFileReader).readNextPacket(packet);
    }
    if (std::holds_alternative<modified_pcap::ZstdModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::ZstdModifiedPcapReader>(mFileReader).
            readNextPacket(packet);
    }
    throw runtime_error("unexpected variant");
}

bool PacketReader::isExhausted() const {
    if (std::holds_alternative<pcap::MMPcapReader>(mFileReader)) {
        return std::get<pcap::MMPcapReader>(mFileReader).isExhausted();
    }
    if (std::holds_alternative<pcap::FReadPcapReader>(mFileReader)) {
        return std::get<pcap::FReadPcapReader>(mFileReader).isExhausted();
    }
    if (std::holds_alternative<pcapng::MMPcapNgReader>(mFileReader)) {
        return std::get<pcapng::MMPcapNgReader>(mFileReader).isExhausted();
    }
    if (std::holds_alternative<pcapng::FReadPcapNgReader>(mFileReader)) {
        return std::get<pcapng::FReadPcapNgReader>(mFileReader).isExhausted();
    }
    if (std::holds_alternative<modified_pcap::MMModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::MMModifiedPcapReader>(mFileReader).isExhausted();
    }
    if (std::holds_alternative<modified_pcap::FReadModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::FReadModifiedPcapReader>(mFileReader).
            isExhausted();
    }
    if (std::holds_alternative<pcap::ZstdPcapReader>(mFileReader)) {
        return std::get<pcap::ZstdPcapReader>(mFileReader).isExhausted();
    }
    if (std::holds_alternative<pcapng::ZstdPcapNgReader>(mFileReader)) {
        return std::get<pcapng::ZstdPcapNgReader>(mFileReader).isExhausted();
    }
    if (std::holds_alternative<modified_pcap::ZstdModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::ZstdModifiedPcapReader>(mFileReader).isExhausted();
    }
    throw runtime_error("unexpected variant");
}

std::string PacketReader::getComment() const {
    if (std::holds_alternative<pcap::MMPcapReader>(mFileReader)) {
        return std::get<pcap::MMPcapReader>(mFileReader).getComment();
    }
    if (std::holds_alternative<pcap::FReadPcapReader>(mFileReader)) {
        return std::get<pcap::FReadPcapReader>(mFileReader).getComment();
    }
    if (std::holds_alternative<pcapng::MMPcapNgReader>(mFileReader)) {
        return std::get<pcapng::MMPcapNgReader>(mFileReader).getComment();
    }
    if (std::holds_alternative<pcapng::FReadPcapNgReader>(mFileReader)) {
        return std::get<pcapng::FReadPcapNgReader>(mFileReader).getComment();
    }
    if (std::holds_alternative<modified_pcap::MMModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::MMModifiedPcapReader>(mFileReader).getComment();
    }
    if (std::holds_alternative<modified_pcap::FReadModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::FReadModifiedPcapReader>(mFileReader).
            getComment();
    }
    if (std::holds_alternative<pcap::ZstdPcapReader>(mFileReader)) {
        return std::get<pcap::ZstdPcapReader>(mFileReader).getComment();
    }
    if (std::holds_alternative<pcapng::ZstdPcapNgReader>(mFileReader)) {
        return std::get<pcapng::ZstdPcapNgReader>(mFileReader).getComment();
    }
    if (std::holds_alternative<modified_pcap::ZstdModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::ZstdModifiedPcapReader>(mFileReader).getComment();
    }
    throw runtime_error("unexpected variant");
}

std::string PacketReader::getOS() const {
    if (std::holds_alternative<pcap::MMPcapReader>(mFileReader)) {
        return std::get<pcap::MMPcapReader>(mFileReader).getOS();
    }
    if (std::holds_alternative<pcap::FReadPcapReader>(mFileReader)) {
        return std::get<pcap::FReadPcapReader>(mFileReader).getOS();
    }
    if (std::holds_alternative<pcapng::MMPcapNgReader>(mFileReader)) {
        return std::get<pcapng::MMPcapNgReader>(mFileReader).getOS();
    }
    if (std::holds_alternative<pcapng::FReadPcapNgReader>(mFileReader)) {
        return std::get<pcapng::FReadPcapNgReader>(mFileReader).getOS();
    }
    if (std::holds_alternative<modified_pcap::MMModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::MMModifiedPcapReader>(mFileReader).getOS();
    }
    if (std::holds_alternative<modified_pcap::FReadModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::FReadModifiedPcapReader>(mFileReader).
            getOS();
    }
    if (std::holds_alternative<pcap::ZstdPcapReader>(mFileReader)) {
        return std::get<pcap::ZstdPcapReader>(mFileReader).getOS();
    }
    if (std::holds_alternative<pcapng::ZstdPcapNgReader>(mFileReader)) {
        return std::get<pcapng::ZstdPcapNgReader>(mFileReader).getOS();
    }
    if (std::holds_alternative<modified_pcap::ZstdModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::ZstdModifiedPcapReader>(mFileReader).getOS();
    }
    throw runtime_error("unexpected variant");
}

std::string PacketReader::getHardware() const {
    if (std::holds_alternative<pcap::MMPcapReader>(mFileReader)) {
        return std::get<pcap::MMPcapReader>(mFileReader).getHardware();
    }
    if (std::holds_alternative<pcap::FReadPcapReader>(mFileReader)) {
        return std::get<pcap::FReadPcapReader>(mFileReader).getHardware();
    }
    if (std::holds_alternative<pcapng::MMPcapNgReader>(mFileReader)) {
        return std::get<pcapng::MMPcapNgReader>(mFileReader).getHardware();
    }
    if (std::holds_alternative<pcapng::FReadPcapNgReader>(mFileReader)) {
        return std::get<pcapng::FReadPcapNgReader>(mFileReader).getHardware();
    }
    if (std::holds_alternative<modified_pcap::MMModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::MMModifiedPcapReader>(mFileReader).getHardware();
    }
    if (std::holds_alternative<modified_pcap::FReadModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::FReadModifiedPcapReader>(mFileReader).
            getHardware();
    }
    if (std::holds_alternative<pcap::ZstdPcapReader>(mFileReader)) {
        return std::get<pcap::ZstdPcapReader>(mFileReader).getHardware();
    }
    if (std::holds_alternative<pcapng::ZstdPcapNgReader>(mFileReader)) {
        return std::get<pcapng::ZstdPcapNgReader>(mFileReader).getHardware();
    }
    if (std::holds_alternative<modified_pcap::ZstdModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::ZstdModifiedPcapReader>(mFileReader).getHardware();
    }
    throw runtime_error("unexpected variant");
}

std::string PacketReader::getUserApplication() const {
    if (std::holds_alternative<pcap::MMPcapReader>(mFileReader)) {
        return std::get<pcap::MMPcapReader>(mFileReader).getUserApplication();
    }
    if (std::holds_alternative<pcap::FReadPcapReader>(mFileReader)) {
        return std::get<pcap::FReadPcapReader>(mFileReader).getUserApplication();
    }
    if (std::holds_alternative<pcapng::MMPcapNgReader>(mFileReader)) {
        return std::get<pcapng::MMPcapNgReader>(mFileReader).getUserApplication();
    }
    if (std::holds_alternative<pcapng::FReadPcapNgReader>(mFileReader)) {
        return std::get<pcapng::FReadPcapNgReader>(mFileReader).getUserApplication();
    }
    if (std::holds_alternative<modified_pcap::MMModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::MMModifiedPcapReader>(mFileReader).
            getUserApplication();
    }
    if (std::holds_alternative<modified_pcap::FReadModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::FReadModifiedPcapReader>(mFileReader).
            getUserApplication();
    }
    if (std::holds_alternative<pcap::ZstdPcapReader>(mFileReader)) {
        return std::get<pcap::ZstdPcapReader>(mFileReader).getUserApplication();
    }
    if (std::holds_alternative<pcapng::ZstdPcapNgReader>(mFileReader)) {
        return std::get<pcapng::ZstdPcapNgReader>(mFileReader).getUserApplication();
    }
    if (std::holds_alternative<modified_pcap::ZstdModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::ZstdModifiedPcapReader>(mFileReader).
            getUserApplication();
    }
    throw runtime_error("unexpected variant");
}

std::vector<TraceInterface> PacketReader::getTraceInterfaces() const {
    if (std::holds_alternative<pcap::MMPcapReader>(mFileReader)) {
        return std::get<pcap::MMPcapReader>(mFileReader).getTraceInterfaces();
    }
    if (std::holds_alternative<pcap::FReadPcapReader>(mFileReader)) {
        return std::get<pcap::FReadPcapReader>(mFileReader).getTraceInterfaces();
    }
    if (std::holds_alternative<pcapng::MMPcapNgReader>(mFileReader)) {
        return std::get<pcapng::MMPcapNgReader>(mFileReader).getTraceInterfaces();
    }
    if (std::holds_alternative<pcapng::FReadPcapNgReader>(mFileReader)) {
        return std::get<pcapng::FReadPcapNgReader>(mFileReader).getTraceInterfaces();
    }
    if (std::holds_alternative<modified_pcap::MMModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::MMModifiedPcapReader>(mFileReader).
            getTraceInterfaces();
    }
    if (std::holds_alternative<modified_pcap::FReadModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::FReadModifiedPcapReader>(mFileReader).
            getTraceInterfaces();
    }
    if (std::holds_alternative<pcap::ZstdPcapReader>(mFileReader)) {
        return std::get<pcap::ZstdPcapReader>(mFileReader).getTraceInterfaces();
    }
    if (std::holds_alternative<pcapng::ZstdPcapNgReader>(mFileReader)) {
        return std::get<pcapng::ZstdPcapNgReader>(mFileReader).getTraceInterfaces();
    }
    if (std::holds_alternative<modified_pcap::ZstdModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::ZstdModifiedPcapReader>(mFileReader).
            getTraceInterfaces();
    }
    throw runtime_error("unexpected variant");
}

TraceInterface PacketReader::getTraceInterface(size_t id) const {
    if (std::holds_alternative<pcap::MMPcapReader>(mFileReader)) {
        return std::get<pcap::MMPcapReader>(mFileReader).getTraceInterface(id);
    }
    if (std::holds_alternative<pcap::FReadPcapReader>(mFileReader)) {
        return std::get<pcap::FReadPcapReader>(mFileReader).getTraceInterface(id);
    }
    if (std::holds_alternative<pcapng::MMPcapNgReader>(mFileReader)) {
        return std::get<pcapng::MMPcapNgReader>(mFileReader).getTraceInterface(id);
    }
    if (std::holds_alternative<pcapng::FReadPcapNgReader>(mFileReader)) {
        return std::get<pcapng::FReadPcapNgReader>(mFileReader).getTraceInterface(id);
    }
    if (std::holds_alternative<modified_pcap::MMModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::MMModifiedPcapReader>(mFileReader).
            getTraceInterface(id);
    }
    if (std::holds_alternative<modified_pcap::FReadModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::FReadModifiedPcapReader>(mFileReader).
            getTraceInterface(id);
    }
    if (std::holds_alternative<pcap::ZstdPcapReader>(mFileReader)) {
        return std::get<pcap::ZstdPcapReader>(mFileReader).getTraceInterface(id);
    }
    if (std::holds_alternative<pcapng::ZstdPcapNgReader>(mFileReader)) {
        return std::get<pcapng::ZstdPcapNgReader>(mFileReader).getTraceInterface(id);
    }
    if (std::holds_alternative<modified_pcap::ZstdModifiedPcapReader>(mFileReader)) {
        return std::get<modified_pcap::ZstdModifiedPcapReader>(mFileReader).
            getTraceInterface(id);
    }
    throw runtime_error("unexpected variant");
}
