#include "fpcap/filesystem/StreamFileWriter.hpp"

namespace fpcap {

StreamFileWriter::StreamFileWriter(const std::string& filepath)
    : FileWriter(filepath),
      mOutputFileStream(mFilepath) {
    if (not mOutputFileStream.is_open()) {
        throw std::runtime_error(
            "could not open output stream: " + std::string(strerror(errno)));
    }
}

void StreamFileWriter::write(const uint8_t* data, const size_t size) {
    mOutputFileStream.write(reinterpret_cast<const char*>(data),
                            static_cast<std::streamsize>(size));
}

} // namespace fpcap
