#ifndef MMPR_UTIL_H
#define MMPR_UTIL_H

#include <cstdint>
#include <cstdio>

namespace mmpr {
namespace util {
static void dumpMemory(const uint8_t* data, size_t length) {
    for (size_t i = 1; i <= length; i++) {
        printf("%02hhx", data[i - 1]);
        if (i % 16 == 0) {
            putchar('\n');
        } else if (i % 8 == 0) {
            printf("  ");
        } else {
            putchar(' ');
        }
    }
    putchar('\n');
}
} // namespace util
} // namespace mmpr

#endif // MMPR_UTIL_H
