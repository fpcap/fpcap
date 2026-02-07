#ifndef FPCAP_PACKETREADER_HPP
#define FPCAP_PACKETREADER_HPP

#include <fpcap/Packet.hpp>
#include <fpcap/PacketIterator.hpp>
#include <fpcap/modified_pcap/ModifiedPcapReader.hpp>
#include <fpcap/pcap/PcapReader.hpp>
#include <fpcap/pcapng/PcapNgReader.hpp>

#include <string>
#include <variant>


namespace fpcap {
class PacketReader {
public:
    explicit PacketReader(const std::string& filepath, bool mmap = true);

    Packet nextPacket();
    bool nextPacket(Packet& packet);

    [[nodiscard]] bool isExhausted() const;
    std::string getFilepath() const { return mFilepath; }

    PacketIterator begin() { return PacketIterator([this](Packet& p) { return nextPacket(p); }); }
    std::default_sentinel_t end() { return {}; }

    std::string getComment() const;
    std::string getOS() const;
    std::string getHardware() const;
    std::string getUserApplication() const;
    std::vector<TraceInterface> getTraceInterfaces() const;
    TraceInterface getTraceInterface(size_t id) const;

private:
    std::string mFilepath;
    std::variant<
        std::monostate,
        pcap::MMPcapReader,
        pcap::FReadPcapReader,
        pcapng::MMPcapNgReader,
        pcapng::FReadPcapNgReader,
        modified_pcap::MMModifiedPcapReader,
        modified_pcap::FReadModifiedPcapReader,
        pcap::ZstdPcapReader,
        pcapng::ZstdPcapNgReader,
        modified_pcap::ZstdModifiedPcapReader
    > mFileReader;
};
}

#endif // FPCAP_PACKETREADER_HPP
