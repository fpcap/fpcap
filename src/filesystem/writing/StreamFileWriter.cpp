#include "mmpr/filesystem/writing/StreamFileWriter.hpp"

namespace mmpr {

StreamFileWriter::StreamFileWriter(const std::string& filepath)
    : FileWriter(filepath), mOutputFileStream(mFilepath) {}

void StreamFileWriter::write(const uint8_t* data, size_t size) {
    mOutputFileStream.write((const char*)data, size);
}

} // namespace mmpr
