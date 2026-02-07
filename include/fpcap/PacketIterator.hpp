#ifndef FPCAP_PACKETITERATOR_HPP
#define FPCAP_PACKETITERATOR_HPP

#include <fpcap/Packet.hpp>

#include <cstddef>
#include <functional>
#include <iterator>

namespace fpcap {
class PacketIterator {
public:
    using iterator_concept = std::input_iterator_tag;
    using value_type = Packet;
    using difference_type = std::ptrdiff_t;

    PacketIterator() = default;

    explicit PacketIterator(std::function<bool(Packet&)> advance)
        : mAdvance(std::move(advance)) {
        next();
    }

    const Packet& operator*() const { return mPacket; }
    const Packet* operator->() const { return &mPacket; }

    PacketIterator& operator++() {
        next();
        return *this;
    }

    void operator++(int) { ++*this; }

    bool operator==(std::default_sentinel_t) const { return mExhausted; }

private:
    void next() {
        if (!mAdvance || !mAdvance(mPacket)) {
            mExhausted = true;
        }
    }

    std::function<bool(Packet&)> mAdvance;
    Packet mPacket{};
    bool mExhausted{false};
};
} // namespace fpcap

#endif // FPCAP_PACKETITERATOR_HPP
