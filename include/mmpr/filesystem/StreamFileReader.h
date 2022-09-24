#ifndef MMPR_STREAMFILEREADER_H
#define MMPR_STREAMFILEREADER_H

#include "FileReader.h"
#include <fstream>

namespace mmpr {

class StreamFileReader : public FileReader {
public:
    StreamFileReader(const std::string& filePath) : FileReader(filePath) {
        mStream = std::ifstream(mFilePath, std::ios::binary);
    }

    std::ifstream mStream;
};

} // namespace mmpr

#endif // MMPR_STREAMFILEREADER_H
