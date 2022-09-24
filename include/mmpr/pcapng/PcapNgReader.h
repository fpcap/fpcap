#ifndef MMPR_PCAPNGREADER_H
#define MMPR_PCAPNGREADER_H

#include "mmpr/mmpr.h"
#include "mmpr/util.h"
#include <algorithm>
#include <filesystem>
#include <stdexcept>

namespace mmpr {

class PcapNgReader : public Reader {
public:
    explicit PcapNgReader(const std::string& filepath) {
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
    virtual uint32_t readBlock() = 0;

    virtual size_t getFileSize() const = 0;
    virtual std::string getFilepath() const = 0;
    virtual size_t getCurrentOffset() const = 0;
    virtual uint16_t getDataLinkType() const { return mDataLinkType; };
    virtual std::string getComment() const { return mMetadata.comment; };
    virtual std::string getOS() const { return mMetadata.os; };
    virtual std::string getHardware() const { return mMetadata.hardware; };
    virtual std::string getUserApplication() const { return mMetadata.userApplication; };
    std::vector<TraceInterface> getTraceInterfaces() const override {
        return mTraceInterfaces;
    }
    TraceInterface getTraceInterface(size_t id) const override {
        if (id >= mTraceInterfaces.size()) {
            throw std::out_of_range("Trace interface index " + std::to_string(id) +
                                    " is out of range");
        }
        return mTraceInterfaces[id];
    }

protected:
    uint16_t mDataLinkType{0};
    std::vector<TraceInterface> mTraceInterfaces;

    struct PcapNgMetadata {
        std::string comment;
        std::string os;
        std::string hardware;
        std::string userApplication;
        // TODO support if_tsresol per interface
        uint32_t timestampResolution{1000000 /* 10^6 */};
    } mMetadata{};
};

} // namespace mmpr

#endif // MMPR_PCAPNGREADER_H
