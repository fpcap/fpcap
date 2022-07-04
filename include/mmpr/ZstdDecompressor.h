#ifndef MMPR_ZSTDDECOMPRESSOR_H
#define MMPR_ZSTDDECOMPRESSOR_H

#include <string>

namespace mmpr {

class ZstdDecompressor {
public:
    static void* decompressFileInMemory(const std::string& filename,
                                        size_t& decompressedSize,
                                        bool mmap = false);

private:
    static void* decompressFileMMAP(const std::string& fname, size_t& decompressedSize);
    static void* decompressFileFRead(const std::string& fname, size_t& decompressedSize);
};

} // namespace mmpr

#endif // MMPR_ZSTDDECOMPRESSOR_H
