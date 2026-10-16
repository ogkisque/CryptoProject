#pragma once
// Базовые байтовые типы и фиксированные идентификаторы.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "vault/common/constants.hpp"

namespace vault {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;
using MutableByteView = std::span<std::uint8_t>;

using Hash256 = std::array<std::uint8_t, kHashSize>;
// Массивы Hash256 (листья, выход batch SHA3) — непрерывный буфер по 32 байта на элемент, без padding;
// именно так они копируются на GPU и обратно.
static_assert(sizeof(Hash256) == kHashSize && alignof(Hash256) == 1, "Hash256 must be a packed 32-byte array");
using StorageUuid = std::array<std::uint8_t, kStorageUuidSize>;
// FileId сравнивается лексикографически по 16 байтам (std::array::operator<=>),
// что и задаёт канонический порядок Merkle leaves (§18).
using FileId = std::array<std::uint8_t, kFileIdSize>;
using Nonce = std::array<std::uint8_t, kNonceSize>;
using GcmTag = std::array<std::uint8_t, kGcmTagSize>;
using WrappedDek = std::array<std::uint8_t, kWrappedDekSize>;

// Строчный hex без разделителей.
std::string to_hex(ByteView data);
// Строгий разбор: только [0-9a-fA-F], чётная длина; std::nullopt при ошибке.
std::optional<Bytes> from_hex(std::string_view hex);
std::optional<FileId> file_id_from_hex(std::string_view hex);

template <std::size_t N>
inline ByteView as_view(const std::array<std::uint8_t, N>& a) {
    return ByteView(a.data(), a.size());
}

inline ByteView as_view(std::string_view s) {
    return ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

// Сравнение за постоянное время (для хешей/идентификаторов из недоверенных данных).
bool constant_time_equal(ByteView a, ByteView b) noexcept;

}  // namespace vault
