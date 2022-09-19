#ifdef MMPR_USE_GZIP

#include "mmpr/GzipDecompressor.h"

#include "mmpr/pcapng/PcapNgBlockParser.h"
#include "zlib.h"
#include <iostream>
#include <stdio.h>
#include <sys/mman.h>

#define CHUNK 16384

using namespace std;

namespace mmpr {

/**
 * Decompress from file source to file dest until stream ends or EOF. inf() returns Z_OK
 * on success, Z_MEM_ERROR if memory could not be allocated for processing, Z_DATA_ERROR
 * if the deflate data is invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h
 * and the version of the library linked do not match, or Z_ERRNO if there is an error
 * reading or writing the files.
 */
void GzipDecompressor::decompress(FILE* source, FILE* dest) {
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        throw runtime_error("Gzip decompression error: inflateInit failed with " +
                            to_string(ret));
    }

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            inflateEnd(&strm);
            throw runtime_error("Gzip decompression error: ferror " + to_string(Z_ERRNO));
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR); /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                inflateEnd(&strm);
                throw std::runtime_error("Gzip decompression error: Z_NEED_DICT");
            case Z_DATA_ERROR:
                inflateEnd(&strm);
                throw std::runtime_error("Gzip decompression error: Z_DATA_ERROR");
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                throw std::runtime_error("Gzip decompression error: Z_MEM_ERROR");
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                inflateEnd(&strm);
                throw std::runtime_error("Gzip decompression error: fwrite");
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    inflateEnd(&strm);
    throw std::runtime_error("Gzip decompression error: inflateEnd Z_DATA_ERROR");
}

size_t GzipDecompressor::decompressedSize(FILE* source) {
    size_t decompressedSize = 0;
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        throw runtime_error("Gzip decompression error: inflateInit failed with " +
                            to_string(ret));
    }

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            inflateEnd(&strm);
            throw runtime_error("Gzip decompression error: ferror " + to_string(Z_ERRNO));
        }
        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR); /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                inflateEnd(&strm);
                throw std::runtime_error("Gzip decompression error: Z_NEED_DICT");
            case Z_DATA_ERROR:
                inflateEnd(&strm);
                throw std::runtime_error("Gzip decompression error: Z_DATA_ERROR");
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                throw std::runtime_error("Gzip decompression error: Z_MEM_ERROR");
            }
            have = CHUNK - strm.avail_out;
            std::cout << "have: " << have << std::endl;
            decompressedSize += have;
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    inflateEnd(&strm);
    return decompressedSize;
}

/* report a zlib or i/o error */
void zerr(int ret) {
    fputs("zpipe: ", stderr);
    switch (ret) {
    case Z_ERRNO:
        if (ferror(stdin))
            fputs("error reading stdin\n", stderr);
        if (ferror(stdout))
            fputs("error writing stdout\n", stderr);
        break;
    case Z_STREAM_ERROR:
        fputs("invalid compression level\n", stderr);
        break;
    case Z_DATA_ERROR:
        fputs("invalid or incomplete deflate data\n", stderr);
        break;
    case Z_MEM_ERROR:
        fputs("out of memory\n", stderr);
        break;
    case Z_VERSION_ERROR:
        fputs("zlib version mismatch!\n", stderr);
    }
}

void* GzipDecompressor::decompressFileInMemory(const std::string& filename,
                                               size_t& decompressedSize,
                                               bool mmap) {
    return decompressFile(filename, decompressedSize);
}

void* GzipDecompressor::decompressFile(const std::string& fname,
                                       size_t& decompressedSize) {
    FILE* inputFd = fopen(fname.c_str(), "rb");
    FILE* outputFd = fopen("unpacked.pcap", "wb");
    GzipDecompressor::decompress(inputFd, outputFd);
//    decompressedSize = GzipDecompressor::decompressedSize(inputFd);
    return new char[decompressedSize];
}

} // namespace mmpr

#endif