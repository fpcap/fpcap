#ifndef MMPR_PCAPNGREADER_H
#define MMPR_PCAPNGREADER_H

#include <boost/filesystem.hpp>
#include <mmpr/mmpr.h>

namespace mmpr {

class PcapNgReader {
public:
    explicit PcapNgReader(const std::string& filepath) : mFilepath(filepath) {
        if (filepath.empty()) {
            throw std::runtime_error("Cannot read empty filepath");
        }

        if (!boost::filesystem::exists(filepath)) {
            throw std::runtime_error("Cannot find file " +
                                     boost::filesystem::absolute(filepath).string());
        }
    };

    virtual void open() = 0;
    virtual void close() = 0;

    virtual bool isExhausted() const { return mOffset >= mFileSize; };
    virtual bool readNextPacket(Packet& packet);
    virtual uint32_t readBlock();

    virtual size_t getFileSize() const { return mFileSize; };
    virtual std::string getFilepath() const { return mFilepath; }
    virtual size_t getCurrentOffset() const { return mOffset; };
    virtual uint16_t getDataLinkType() const { return mDataLinkType; };
    virtual std::string getComment() const { return mMetadata.comment; };
    virtual std::string getOS() const { return mMetadata.os; };
    virtual std::string getHardware() const { return mMetadata.hardware; };
    virtual std::string getUserApplication() const { return mMetadata.userApplication; };

protected:
    std::string mFilepath;
    size_t mFileSize{0};
    size_t mOffset{0};
    const uint8_t* mData{nullptr};
    uint16_t mDataLinkType{0};

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
