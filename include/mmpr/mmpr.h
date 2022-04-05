#ifndef MMPR_MMPR_H
#define MMPR_MMPR_H

#include <cstdint>
#include <cassert>
#include <mmpr/pcap.h>
#include <mmpr/pcapng.h>

#if DEBUG
#define MMPR_DEBUG_LOG(format, val) printf(format, val);
#define MMPR_DEBUG_LOG_2(format, val1, val2) printf(format, val1, val2);
#define MMPR_ASSERT(x) assert(x)
#else
#define MMPR_DEBUG_LOG(format, val) while (0)
#define MMPR_DEBUG_LOG_2(format, val1, val2) while (0)
#define MMPR_ASSERT(x) (void)(x)
#endif
#define MMPR_WARN(msg) fprintf(stderr, msg)
#define MMPR_WARN_1(msg, val) fprintf(stderr, msg, val)
#define MMPR_UNUSED(x) (void)(x)

#define MMPR_PAGE_SIZE 4096

namespace mmpr {

struct Packet {
    uint32_t timestampSeconds{0};
    uint32_t timestampMicroseconds{0};
    uint32_t captureLength{0};
    uint32_t length{0};
    const uint8_t* data{nullptr};
};

} // namespace mmpr

#endif // MMPR_MMPR_H
