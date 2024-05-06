#ifndef FPCAP_FILEWRITER_HPP
#define FPCAP_FILEWRITER_HPP

#include "fpcap/fpcap.hpp"
#include <string>
#include <vector>

namespace fpcap {

class FileWriter {
public:
    FileWriter(const std::string& filepath);
    virtual ~FileWriter();

    virtual void write(const uint8_t* data, size_t size) = 0;
    virtual void write(int64_t data) = 0;
    virtual void write(uint32_t data) = 0;
    virtual void write(uint16_t data) = 0;
    virtual void write(uint8_t data) = 0;

protected:
    const std::string mFilepath;
};

} // namespace fpcap

#endif // FPCAP_FILEWRITER_HPP
