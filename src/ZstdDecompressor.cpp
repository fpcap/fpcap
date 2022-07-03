#ifdef MMPR_USE_ZSTD

#include "mmpr/ZstdDecompressor.h"

#include "mmpr/pcapng/PcapNgBlockParser.h"
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <sys/mman.h>
#include <unistd.h>
#include <zstd.h>

using namespace std;

namespace mmpr {

void* ZstdDecompressor::decompressFileInMemory(const std::string& fname,
                                               size_t& decompressedSize) {
    int fd = ::open(fname.c_str(), O_RDONLY, 0);
    if (fd < 0) {
        throw runtime_error("Error while reading file " +
                            std::filesystem::absolute(fname).string() + ": " +
                            strerror(errno));
    }

    size_t compressedSize = lseek(fd, 0, SEEK_END);
    size_t mappedSize = (compressedSize / MMPR_PAGE_SIZE + 1) * MMPR_PAGE_SIZE;

    void* const compressedData = mmap(nullptr, mappedSize, PROT_READ, MAP_SHARED, fd, 0);
    if (compressedData == MAP_FAILED) {
        ::close(fd);
        throw runtime_error("Error while mapping file " +
                            std::filesystem::absolute(fname).string() + ": " +
                            strerror(errno));
    }

    /* Read the content size from the frame header. For simplicity we require
     * that it is always present. By default, zstd will write the content size
     * in the header when it is known. If you can't guarantee that the frame
     * content size is always written into the header, either use streaming
     * decompression, or ZSTD_decompressBound().
     */
    unsigned long long const decompressedFileSize =
        ZSTD_getFrameContentSize(compressedData, compressedSize);
    if (decompressedFileSize == ZSTD_CONTENTSIZE_ERROR) {
        throw runtime_error(fname + " is not compressed by zstd");
    }
    if (decompressedFileSize == ZSTD_CONTENTSIZE_UNKNOWN) {
        throw runtime_error(fname + " original size unknown");
    }

    void* const decompressedData = malloc(decompressedFileSize);
    if (!decompressedData) {
        throw runtime_error("Unable to malloc " + to_string(decompressedFileSize) +
                            " for decompressed file");
    }

    /* Decompress.
     * If you are doing many decompressions, you may want to reuse the context
     * and use ZSTD_decompressDCtx(). If you want to set advanced parameters,
     * use ZSTD_DCtx_setParameter().
     */
    decompressedSize = ZSTD_decompress(decompressedData, decompressedFileSize,
                                       compressedData, compressedSize);
    if (ZSTD_isError(decompressedSize)) {
        throw runtime_error(ZSTD_getErrorName(decompressedSize));
    }

    // When zstd knows the content size, it will error if it doesn't match.
    if (decompressedSize != decompressedFileSize) {
        throw runtime_error("Content size does not match");
    }

    // unmap memory mapped file and close file descriptor
    munmap((void*)compressedData, mappedSize);
    ::close(fd);

    return decompressedData;
}

} // namespace mmpr

#endif