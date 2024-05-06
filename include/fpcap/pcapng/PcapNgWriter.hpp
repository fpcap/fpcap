#ifndef FPCAP_PCAPNGWRITER_HPP
#define FPCAP_PCAPNGWRITER_HPP

#include "fpcap/filesystem/writing/FileWriter.hpp"
#include "fpcap/filesystem/writing/StreamFileWriter.hpp"
#include "fpcap/fpcap.hpp"

namespace fpcap {

template <typename TWriter>
class PcapNgWriter : public Writer {
    static_assert(std::is_base_of_v<FileWriter, TWriter>,
                  "TWriter must be a subclass of FileWriter");

public:
    explicit PcapNgWriter(const std::string& filepath);

    void write(const Packet& packet) override;

    void writePacket(const Packet& packet, uint32_t interfaceId);
    void writeSHB(const pcapng::SectionHeaderBlock& shb);
    void writeIDB(const pcapng::InterfaceDescriptionBlock& idb);
    void writeEPB(const pcapng::EnhancedPacketBlock& epb);

private:
    TWriter mWriter;
};

typedef PcapNgWriter<StreamFileWriter> StreamPcapNgWriter;

} // namespace fpcap

#endif // FPCAP_PCAPNGWRITER_HPP
