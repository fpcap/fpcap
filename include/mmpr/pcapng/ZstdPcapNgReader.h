#ifndef MMPR_ZSTDPCAPNGREADER_H
#define MMPR_ZSTDPCAPNGREADER_H

#include <mmpr/pcapng/PcapNgReader.h>

namespace mmpr {

class ZstdPcapNgReader : public PcapNgReader {
public:
    explicit ZstdPcapNgReader(const std::string& filepath);

    void open() override;
    void close() override;
};

} // namespace mmpr

#endif // MMPR_ZSTDPCAPNGREADER_H
