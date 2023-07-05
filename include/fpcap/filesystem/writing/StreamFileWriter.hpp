#ifndef FPCAP_STREAMFILEWRITER_HPP
#define FPCAP_STREAMFILEWRITER_HPP

#include "fpcap/filesystem/writing/FileWriter.hpp"
#include <fstream>

namespace fpcap {

class StreamFileWriter : public FileWriter {
public:
    StreamFileWriter(const std::string& filepath);

    void write(const uint8_t* data, size_t size) override;

private:
    std::ofstream mOutputFileStream;
};

} // namespace fpcap

#endif // FPCAP_STREAMFILEWRITER_HPP
