#include "fpcap/filesystem/Writer.hpp"

#include <fpcap/pcap/PcapWriter.hpp>

using namespace std;

namespace fpcap {

unique_ptr<Writer> Writer::getWriter(const string& filepath, bool append) {
    if (filepath.empty()) {
        throw runtime_error("cannot writer reader for empty filepath");
    }

    return make_unique<pcap::StreamPcapWriter>(filepath, append);
}

} // namespace fpcap
