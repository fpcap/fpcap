#ifndef MMPR_ZSTDDECOMPRESSOR_H
#define MMPR_ZSTDDECOMPRESSOR_H

#include <string>

namespace mmpr {

class ZstdDecompressor {
public:
    static void* decompressFileInMemory(const std::string& filename,
                                        size_t& decompressedSize);
};

} // namespace mmpr

#endif // MMPR_ZSTDDECOMPRESSOR_H
