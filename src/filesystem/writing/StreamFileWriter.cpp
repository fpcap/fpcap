#include "fpcap/filesystem/writing/StreamFileWriter.hpp"

namespace fpcap {

StreamFileWriter::StreamFileWriter(const std::string& filepath)
    : FileWriter(filepath), mOutputFileStream(mFilepath) {}

void StreamFileWriter::write(const uint8_t* data, const size_t size) {
    mOutputFileStream.write(reinterpret_cast<const char*>(data),
                            static_cast<std::streamsize>(size));
}

void StreamFileWriter::write(const int64_t data) {
    mOutputFileStream.write(reinterpret_cast<const char*>(&data), sizeof(int64_t));
}

void StreamFileWriter::write(const uint32_t data) {
    mOutputFileStream.write(reinterpret_cast<const char*>(&data), sizeof(uint32_t));
}

void StreamFileWriter::write(const uint16_t data) {
    mOutputFileStream.write(reinterpret_cast<const char*>(&data), sizeof(uint16_t));
}

void StreamFileWriter::write(const uint8_t data) {
    mOutputFileStream.write(reinterpret_cast<const char*>(&data), sizeof(uint8_t));
}

} // namespace fpcap
