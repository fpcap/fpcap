#ifndef FPCAP_PCAPWRITER_HPP
#define FPCAP_PCAPWRITER_HPP

#include "fpcap/fpcap.hpp"
#include "fpcap/filesystem/writing/FileWriter.hpp"
#include "fpcap/filesystem/writing/StreamFileWriter.hpp"

namespace fpcap {

template <typename TWriter>
class PcapWriter : public Writer {
    static_assert(std::is_base_of<FileWriter, TWriter>::value,
                  "TWriter must be a subclass of FileWriter");

public:
    PcapWriter(const std::string& filepath);

    void write(const Packet& packet) override;

private:
    void writePcapHeader();

    TWriter mWriter;
};

typedef PcapWriter<StreamFileWriter> StreamPcapWriter;

} // namespace fpcap

#endif // FPCAP_PCAPWRITER_HPP
