#ifndef FPCAP_STREAMFILEWRITER_HPP
#define FPCAP_STREAMFILEWRITER_HPP

#include <fpcap/filesystem/FileWriter.hpp>

#include <fstream>

namespace fpcap {
class StreamFileWriter final : public FileWriter {
public:
    explicit StreamFileWriter(const std::string& filepath, bool append);

    void write(const uint8_t* data, size_t size) override;

private:
    std::ofstream mOutputFileStream;
};
} // namespace fpcap

#endif // FPCAP_STREAMFILEWRITER_HPP
