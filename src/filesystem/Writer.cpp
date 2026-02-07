#include "fpcap/filesystem/Writer.hpp"

#include <fpcap/pcap/PcapWriter.hpp>
#include <fpcap/pcapng/PcapNgWriter.hpp>

using namespace std;

namespace fpcap {

unique_ptr<Writer>
Writer::getWriter(const string& filepath, bool append, const WriterFormat format) {
    if (filepath.empty()) {
        throw runtime_error("cannot writer reader for empty filepath");
    }

    switch (format) {
    case WriterFormat::PCAPNG:
        return make_unique<pcapng::StreamPcapNgWriter>(filepath, append);
    case WriterFormat::PCAP:
        return make_unique<pcap::StreamPcapWriter>(filepath, append);
    case WriterFormat::AUTO:
    default:
        if (filepath.size() >= 7 && filepath.substr(filepath.size() - 7) == ".pcapng") {
            return make_unique<pcapng::StreamPcapNgWriter>(filepath, append);
        }
        return make_unique<pcap::StreamPcapWriter>(filepath, append);
    }
}

} // namespace fpcap
