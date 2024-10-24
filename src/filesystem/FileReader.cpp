#include "fpcap/filesystem/FileReader.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>

using namespace std;
using namespace std::filesystem;

namespace fpcap {

FileReader::FileReader(const string& filepath)
    : mFilepath(filepath) {
    if (filepath.empty()) {
        throw runtime_error("Cannot read empty filepath");
    }

    if (!exists(filepath)) {
        throw runtime_error("Cannot find file " + absolute(filepath).string());
    }

    mFileSize = file_size(filepath);
}

size_t FileReader::getSafeToReadSize() const {
    if (mOffset >= mFileSize) {
        return 0;
    }

    return mFileSize - mOffset;
}

} // namespace fpcap
