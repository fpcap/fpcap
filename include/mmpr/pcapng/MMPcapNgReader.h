#ifndef MMPR_MMPCAPNGREADER_H
#define MMPR_MMPCAPNGREADER_H

#include <mmpr/pcapng/PcapNgReader.h>

namespace mmpr {
class MMPcapNgReader : public PcapNgReader {
public:
    explicit MMPcapNgReader(const std::string& filepath);

    void open() override;
    void close() override;

private:
    int mFileDescriptor{0};
    size_t mMappedSize{0};
};
} // namespace mmpr

#endif // MMPR_MMPCAPNGREADER_H
