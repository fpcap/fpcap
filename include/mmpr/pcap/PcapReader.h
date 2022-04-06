#ifndef MMPR_PCAPREADER_H
#define MMPR_PCAPREADER_H

#include <boost/filesystem.hpp>
#include <mmpr/mmpr.h>

namespace mmpr {

class PcapReader : public FileReader {
public:
    explicit PcapReader(const std::string& filepath) : FileReader(filepath) {
        if (filepath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!boost::filesystem::exists(filepath)) {
            throw std::runtime_error("Cannot find file " +
                                     boost::filesystem::absolute(filepath).string());
        }
    };

    virtual void open() = 0;
    virtual bool isExhausted() const = 0;
    virtual bool readNextPacket(Packet& packet) = 0;
    virtual void close() = 0;

    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const { return mFilepath; }
    virtual size_t getCurrentOffset() const = 0;
    virtual uint16_t getDataLinkType() const { return mDataLinkType; };

protected:
    uint16_t mDataLinkType{0};
};

} // namespace mmpr

#endif // MMPR_PCAPREADER_H
