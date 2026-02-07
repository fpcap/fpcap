#ifndef FPCAP_PCAPNGWRITER_HPP
#define FPCAP_PCAPNGWRITER_HPP

#include <fpcap/Constants.hpp>
#include <fpcap/Packet.hpp>
#include <fpcap/filesystem/FileWriter.hpp>
#include <fpcap/filesystem/StreamFileWriter.hpp>
#include <fpcap/filesystem/Writer.hpp>

namespace fpcap::pcapng {

template <typename TWriter>
class PcapNgWriter final : public Writer {
    static_assert(std::is_base_of_v<FileWriter, TWriter>,
                  "TWriter must be a subclass of FileWriter");

public:
    explicit PcapNgWriter(const std::string& filepath,
                          bool append,
                          uint16_t linkType = DLT_EN10MB);

    void write(const Packet& packet) override;

private:
    void writeSectionHeaderBlock();
    void writeInterfaceDescriptionBlock();

    TWriter mWriter;
    uint16_t mLinkType;
};

typedef PcapNgWriter<StreamFileWriter> StreamPcapNgWriter;

} // namespace fpcap::pcapng

#endif // FPCAP_PCAPNGWRITER_HPP
