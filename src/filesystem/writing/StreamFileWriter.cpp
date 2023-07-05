#include "fpcap/filesystem/writing/StreamFileWriter.hpp"

namespace fpcap {

StreamFileWriter::StreamFileWriter(const std::string& filepath)
    : FileWriter(filepath), mOutputFileStream(mFilepath) {}

void StreamFileWriter::write(const uint8_t* data, size_t size) {
    mOutputFileStream.write((const char*)data, static_cast<std::streamsize>(size));
}

} // namespace fpcap
