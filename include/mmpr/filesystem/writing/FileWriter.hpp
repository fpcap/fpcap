#ifndef MMPR_FILEWRITER_HPP
#define MMPR_FILEWRITER_HPP

#include "mmpr/mmpr.hpp"
#include <string>
#include <vector>

namespace mmpr {

class FileWriter {
public:
    FileWriter(const std::string& filepath) : mFilepath(filepath) {}

    virtual void write(const uint8_t* data, size_t size) = 0;

protected:
    const std::string mFilepath;
};

} // namespace mmpr

#endif // MMPR_FILEWRITER_HPP
