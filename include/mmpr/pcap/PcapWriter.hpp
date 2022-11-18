#ifndef MMPR_PCAPWRITER_HPP
#define MMPR_PCAPWRITER_HPP

#include "mmpr/filesystem/writing/FileWriter.hpp"
#include "mmpr/filesystem/writing/StreamFileWriter.hpp"
#include "mmpr/mmpr.hpp"

namespace mmpr {

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

template class PcapWriter<StreamFileWriter>;

typedef PcapWriter<StreamFileWriter> StreamPcapWriter;

} // namespace mmpr

#endif // MMPR_PCAPWRITER_HPP
