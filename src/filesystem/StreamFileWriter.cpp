#include "fpcap/filesystem/StreamFileWriter.hpp"

#include <cstring>

namespace fpcap {

StreamFileWriter::StreamFileWriter(const std::string& filepath, bool append)
    : FileWriter(filepath),
      mOutputFileStream(mFilepath,
                        append
                            ? std::ofstream::binary | std::ofstream::app
                            : std::ofstream::binary) {
    if (not mOutputFileStream.is_open()) {
        throw std::system_error(errno, std::system_category(),
                                "could not open output stream");
    }
}

void StreamFileWriter::write(const uint8_t* data, const size_t size) {
    mOutputFileStream.write(reinterpret_cast<const char*>(data),
                            static_cast<std::streamsize>(size));
}

} // namespace fpcap
