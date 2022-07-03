#ifndef MMPR_PCAPREADER_H
#define MMPR_PCAPREADER_H

#include <filesystem>
#include <mmpr/mmpr.h>
#include <stdexcept>

namespace mmpr {

class PcapReader : public FileReader {
public:
    explicit PcapReader(const std::string& filepath) : FileReader(filepath) {
        if (filepath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!std::filesystem::exists(filepath)) {
            throw std::runtime_error("Cannot find file " +
                                     std::filesystem::absolute(filepath).string());
        }
    };

    virtual void open() = 0;
    virtual bool isExhausted() const = 0;
    virtual bool readNextPacket(Packet& packet) = 0;
    virtual void close() = 0;

    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const override { return mFilepath; }
    virtual size_t getCurrentOffset() const = 0;
    virtual uint16_t getDataLinkType() const override { return mDataLinkType; };
    std::vector<TraceInterface> getTraceInterfaces() const override {
        return std::vector<TraceInterface>();
    }
    TraceInterface getTraceInterface(__attribute__((unused)) size_t id) const override {
        return {};
    }

protected:
    uint16_t mDataLinkType{0};
};

} // namespace mmpr

#endif // MMPR_PCAPREADER_H
