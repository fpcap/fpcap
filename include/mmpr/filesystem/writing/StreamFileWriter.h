#ifndef MMPR_STREAMFILEWRITER_H
#define MMPR_STREAMFILEWRITER_H

#include "mmpr/filesystem/writing/FileWriter.h"
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

#endif // MMPR_STREAMFILEWRITER_H
