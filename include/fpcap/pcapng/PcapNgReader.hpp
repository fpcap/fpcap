#ifndef FPCAP_PCAPNGREADER_HPP
#define FPCAP_PCAPNGREADER_HPP

#include <fpcap/filesystem/Reader.hpp>
#include <fpcap/filesystem/FReadFileReader.hpp>
#include <fpcap/filesystem/FileReader.hpp>
#include <fpcap/filesystem/MMapFileReader.hpp>
#include <fpcap/filesystem/ZstdFileReader.hpp>

#include <filesystem>

namespace fpcap::pcapng {
template <typename TReader>
class PcapNgReader final : public Reader {
    static_assert(std::is_base_of_v<FileReader, TReader>,
                  "TReader must be a subclass of FileReader");

public:
    explicit PcapNgReader(const std::string& filepath);

    explicit PcapNgReader(TReader&& reader);

    bool isExhausted() const override;

    bool readNextPacket(Packet& packet) override;

    /**
     * 3.1.  General Block Structure
     *
     *                        1                   2                   3
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 0 |                          Block Type                           |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 4 |                      Block Total Length                       |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 8 /                          Block Body                           /
     *   /              variable length, padded to 32 bits               /
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |                      Block Total Length                       |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    uint32_t readBlock() override;

    size_t getFileSize() const override { return mReader.mFileSize; }

    std::string getFilepath() const override { return mReader.mFilepath; }

    size_t getCurrentOffset() const override { return mReader.mOffset; }

    std::string getComment() const override { return mMetadata.comment; }

    std::string getOS() const override { return mMetadata.os; }

    std::string getHardware() const override { return mMetadata.hardware; }

    std::string getUserApplication() const override { return mMetadata.userApplication; }

    std::vector<TraceInterface> getTraceInterfaces() const override {
        return mTraceInterfaces;
    }

    TraceInterface getTraceInterface(size_t id) const override;

    /**
     * Eagerly reads all blocks preceding the first packet block (SHB, IDBs, etc.),
     * populating metadata and trace interfaces so they are available immediately
     * after construction.
     */
    void readPreamble();

private:
    TReader mReader;
    std::vector<TraceInterface> mTraceInterfaces;

    struct PcapNgMetadata {
        std::string comment;
        std::string os;
        std::string hardware;
        std::string userApplication;
    } mMetadata{};
};

typedef PcapNgReader<FReadFileReader> FReadPcapNgReader;
typedef PcapNgReader<MMapFileReader> MMPcapNgReader;
typedef PcapNgReader<ZstdFileReader> ZstdPcapNgReader;
} // namespace fpcap::pcapng

#endif // FPCAP_PCAPNGREADER_HPP
