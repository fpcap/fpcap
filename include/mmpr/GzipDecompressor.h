#ifndef MMPR_GZIPDECOMPRESSOR_H
#define MMPR_GZIPDECOMPRESSOR_H

#include <string>

namespace mmpr {

class GzipDecompressor {
public:
    static void* decompressFileInMemory(const std::string& filename,
                                        size_t& decompressedSize,
                                        bool mmap = false);

private:
    static void decompress(FILE* source, FILE* dest);
    static size_t decompressedSize(FILE *source);
    static void* decompressFile(const std::string& fname, size_t& decompressedSize);
};

} // namespace mmpr

#endif // MMPR_GZIPDECOMPRESSOR_H
