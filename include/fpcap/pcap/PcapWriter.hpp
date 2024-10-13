#ifndef FPCAP_PCAPWRITER_HPP
#define FPCAP_PCAPWRITER_HPP

#include <fpcap/Packet.hpp>
#include <fpcap/filesystem/Writer.hpp>
#include <fpcap/filesystem/FileWriter.hpp>
#include <fpcap/filesystem/StreamFileWriter.hpp>

namespace fpcap::pcap {
template <typename TWriter>
class PcapWriter final : public Writer {
    static_assert(std::is_base_of_v<FileWriter, TWriter>,
                  "TWriter must be a subclass of FileWriter");

public:
    explicit PcapWriter(const std::string& filepath);

    void write(const Packet& packet) override;

private:
    void writePcapHeader();

    TWriter mWriter;
};

typedef PcapWriter<StreamFileWriter> StreamPcapWriter;
} // namespace fpcap::pcap

#endif // FPCAP_PCAPWRITER_HPP
