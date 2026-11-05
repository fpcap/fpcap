#ifndef FPCAP_TESTS_BLOCKTESTUTIL_HPP
#define FPCAP_TESTS_BLOCKTESTUTIL_HPP

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace fpcap::test {

// Copies a block so that it ends exactly at the end of its allocation. The 4 byte lead
// into the 8 byte aligned allocation keeps 8 byte reads straddling the block end
// aligned, which ASan checks in full.
class ExactBlock {
public:
    explicit ExactBlock(const std::vector<uint32_t>& words)
        : mBuffer(std::make_unique<uint8_t[]>(4 + words.size() * sizeof(uint32_t))) {
        std::memcpy(mBuffer.get() + 4, words.data(), words.size() * sizeof(uint32_t));
    }

    const uint8_t* get() const { return mBuffer.get() + 4; }

private:
    std::unique_ptr<uint8_t[]> mBuffer;
};

constexpr uint32_t optionHeader(const uint16_t type, const uint16_t length) {
    return type | static_cast<uint32_t>(length) << 16;
}

} // namespace fpcap::test

#endif // FPCAP_TESTS_BLOCKTESTUTIL_HPP
