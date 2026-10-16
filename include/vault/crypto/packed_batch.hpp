#pragma once
// Единый плоский формат пакета входов переменной длины («offsets + data»):
//   data    — все элементы подряд, без padding и разделителей;
//   offsets — count + 1 значений u64, элемент i = data[offsets[i], offsets[i+1]).
// В таком виде SHA3-batch уходит на GPU одним H2D-копированием; CPU backend'ы используют
// std::span<const ByteView>, и обе формы взаимно преобразуются без потерь.

#include <cstdint>
#include <span>
#include <vector>

#include "vault/common/bytes.hpp"

namespace vault::crypto {

struct PackedBatch {
    Bytes data;
    std::vector<std::uint64_t> offsets{0};

    std::size_t count() const noexcept { return offsets.size() - 1; }
    ByteView element(std::size_t i) const {
        return ByteView(data.data() + offsets[i], static_cast<std::size_t>(offsets[i + 1] - offsets[i]));
    }
    std::vector<ByteView> views() const {
        std::vector<ByteView> v;
        v.reserve(count());
        for (std::size_t i = 0; i < count(); ++i) v.push_back(element(i));
        return v;
    }

    static PackedBatch pack(std::span<const ByteView> inputs) {
        PackedBatch p;
        std::size_t total = 0;
        for (const auto& in : inputs) total += in.size();
        p.data.reserve(total);
        p.offsets.reserve(inputs.size() + 1);
        for (const auto& in : inputs) {
            p.data.insert(p.data.end(), in.begin(), in.end());
            p.offsets.push_back(p.data.size());
        }
        return p;
    }
};

}  // namespace vault::crypto
