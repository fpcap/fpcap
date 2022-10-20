#ifndef MMPR_STREAMFILEWRITER_HPP
#define MMPR_STREAMFILEWRITER_HPP

#include "mmpr/filesystem/writing/FileWriter.hpp"
#include <fstream>

namespace mmpr {

class StreamFileWriter : public FileWriter {
public:
    StreamFileWriter(const std::string& filepath)
        : FileWriter(filepath), mOutputFileStream(mFilepath) {}

    void write(const uint8_t* data, size_t size) override {
        mOutputFileStream.write((const char*)data, size);
    }

private:
    std::ofstream mOutputFileStream;
};

} // namespace mmpr

#endif // MMPR_STREAMFILEWRITER_HPP
