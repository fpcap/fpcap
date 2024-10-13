#ifndef FPCAP_FILEWRITER_HPP
#define FPCAP_FILEWRITER_HPP

#include <string>
#include <cstdint>

namespace fpcap {
class FileWriter {
public:
    explicit FileWriter(const std::string& filepath);
    virtual ~FileWriter();

    virtual void write(const uint8_t* data, size_t size) = 0;

protected:
    const std::string mFilepath;
};
} // namespace fpcap

#endif // FPCAP_FILEWRITER_HPP
