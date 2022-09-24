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

void* ZstdDecompressor::decompressFileInMemory(const std::string& filename,
                                               size_t& decompressedSize,
                                               bool mmap) {
    if (mmap) {
        return decompressFileMMAP(filename, decompressedSize);
    } else {
        return decompressFileFRead(filename, decompressedSize);
    }
}

void* ZstdDecompressor::decompressFileMMAP(const std::string& fname,
                                           size_t& decompressedSize) {
    int fd = ::open(fname.c_str(), O_RDONLY, 0);
    if (fd < 0) {
        throw runtime_error("Error while reading file " +
                            std::filesystem::absolute(fname).string() + ": " +
                            strerror(errno));
    }

    size_t compressedSize = lseek(fd, 0, SEEK_END);
    long pageSize = sysconf (_SC_PAGESIZE);
    size_t mappedSize = (compressedSize / pageSize + 1) * pageSize;

    void* const compressedData = mmap(nullptr, mappedSize, PROT_READ, MAP_SHARED, fd, 0);
    if (compressedData == MAP_FAILED) {
        ::close(fd);
        throw runtime_error("Error while mapping file " +
                            std::filesystem::absolute(fname).string() + ": " +
                            strerror(errno));
    }

    /* Read the content size from the frame header. For simplicity, we require
     * that it is always present. By default, zstd will write the content size
     * in the header when it is known. If you can't guarantee that the frame
     * content size is always written into the header, either use streaming
     * decompression, or ZSTD_decompressBound().
     */
    auto decompressedFileSize = ZSTD_getFrameContentSize(compressedData, compressedSize);
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

void* ZstdDecompressor::decompressFileFRead(const std::string& fname,
                                            size_t& decompressedSize) {
    size_t compressedSize = std::filesystem::file_size(fname);
    char* compressedData = new char[compressedSize];
    FILE* const inFile = fopen(fname.c_str(), "rb");
    if (fread(compressedData, 1, compressedSize, inFile) != compressedSize) {
        delete[] compressedData;
        throw runtime_error("fread error: " + std::string(strerror(errno)));
    }
    fclose(inFile);

    /* Read the content size from the frame header. For simplicity, we require
     * that it is always present. By default, zstd will write the content size
     * in the header when it is known. If you can't guarantee that the frame
     * content size is always written into the header, either use streaming
     * decompression, or ZSTD_decompressBound().
     */
    auto decompressedFileSize = ZSTD_getFrameContentSize(compressedData, compressedSize);
    if (decompressedFileSize == ZSTD_CONTENTSIZE_ERROR) {
        delete[] compressedData;
        throw runtime_error("not compressed by zstd!");
    }
    if (decompressedFileSize == ZSTD_CONTENTSIZE_UNKNOWN) {
        delete[] compressedData;
        throw runtime_error("original size unknown!");
    }

    char* decompressedData = new char[decompressedFileSize];

    /* Decompress.
     * If you are doing many decompressions, you may want to reuse the context
     * and use ZSTD_decompressDCtx(). If you want to set advanced parameters,
     * use ZSTD_DCtx_setParameter().
     */
    decompressedSize = ZSTD_decompress(decompressedData, decompressedFileSize,
                                       compressedData, compressedSize);
    if (ZSTD_isError(decompressedSize)) {
        delete[] compressedData;
        delete[] decompressedData;
        throw runtime_error(ZSTD_getErrorName(decompressedSize));
    }

    // When zstd knows the content size, it will error if it doesn't match.
    if (decompressedSize != decompressedFileSize) {
        delete[] compressedData;
        delete[] decompressedData;
        throw runtime_error("Impossible because zstd will check this condition!");
    }

    delete[] compressedData;

    return decompressedData;
}

} // namespace mmpr

#endif