#ifndef MMPR_RAWREADER_H
#define MMPR_RAWREADER_H

#include "mmpr/mmpr.h"
#include <filesystem>
#include <stdexcept>

namespace mmpr {
class ModifiedPcapReader : public FileReader {
public:
    explicit ModifiedPcapReader(const std::string& filepath) : FileReader(filepath) {
        if (filepath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!std::filesystem::exists(filepath)) {
            throw std::runtime_error("Cannot find file " +
                                     std::filesystem::absolute(filepath).string());
        }
    };

    virtual void open() override = 0;
    virtual bool isExhausted() const override = 0;
    virtual bool readNextPacket(Packet& packet) override = 0;
    virtual void close() override = 0;

    virtual size_t getFileSize() const override = 0;
    virtual std::string getFilepath() const override { return mFilepath; }
    virtual size_t getCurrentOffset() const override = 0;
    virtual uint16_t getDataLinkType() const override { return mDataLinkType; };
    std::vector<TraceInterface> getTraceInterfaces() const override {
        return std::vector<TraceInterface>();
    }
    TraceInterface getTraceInterface(__attribute__((unused)) size_t id) const override {
        return {};
    }

protected:
    uint16_t mDataLinkType{101};
};

} // namespace mmpr

#endif // MMPR_RAWREADER_H
