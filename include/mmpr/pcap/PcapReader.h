#ifndef MMPR_PCAPREADER_H
#define MMPR_PCAPREADER_H

#include "mmpr/mmpr.h"
#include <filesystem>
#include <stdexcept>

namespace mmpr {

class PcapReader : public Reader {
public:
    explicit PcapReader(const std::string& filepath) {
        if (filepath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!std::filesystem::exists(filepath)) {
            throw std::runtime_error("Cannot find file " +
                                     std::filesystem::absolute(filepath).string());
        }
    };

    virtual bool isExhausted() const = 0;
    virtual bool readNextPacket(Packet& packet) = 0;

    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const override = 0;
    virtual size_t getCurrentOffset() const = 0;
    virtual uint16_t getDataLinkType() const override { return mDataLinkType; };
    std::vector<TraceInterface> getTraceInterfaces() const override {
        return std::vector<TraceInterface>();
    }
    TraceInterface getTraceInterface([[maybe_unused]] size_t id) const override {
        return {};
    }

protected:
    uint16_t mDataLinkType{0};
};

} // namespace mmpr

#endif // MMPR_PCAPREADER_H
