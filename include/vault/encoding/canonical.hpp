#pragma once
// Каноническое бинарное кодирование v1 (§12): u32/u64 big-endian,
// фиксированные массивы — ровно N байт, переменные — только с явной длиной.
// ByteReader строгий: любое несоответствие -> VaultError(FormatError).

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

#include "vault/common/bytes.hpp"

namespace vault::encoding {

class ByteWriter {
public:
    ByteWriter() = default;
    explicit ByteWriter(std::size_t reserve);

    void u32(std::uint32_t v);
    void u64(std::uint64_t v);
    void u8(std::uint8_t v);
    void fixed(ByteView data);  // ровно data.size() байт, без длины
    template <std::size_t N>
    void fixed(const std::array<std::uint8_t, N>& a) { fixed(as_view(a)); }
    void var_u32(ByteView data);  // u32 length || data
    void var_u64(ByteView data);  // u64 length || data

    const Bytes& bytes() const noexcept { return out_; }
    Bytes take() && { return std::move(out_); }
    std::size_t size() const noexcept { return out_.size(); }

private:
    Bytes out_;
};

class ByteReader {
public:
    explicit ByteReader(ByteView in) : in_(in) {}

    std::uint32_t u32();
    std::uint64_t u64();
    std::uint8_t u8();
    ByteView fixed(std::size_t n);  // view внутрь входного буфера
    template <std::size_t N>
    std::array<std::uint8_t, N> fixed_array();
    // Длина проверяется против remaining() ДО выделения памяти.
    ByteView var_u32(std::uint32_t max_len);
    ByteView var_u64(std::uint64_t max_len);

    std::size_t remaining() const noexcept { return in_.size() - pos_; }
    std::size_t position() const noexcept { return pos_; }
    // Бросает FormatError, если остались непрочитанные байты (trailing data).
    void expect_end() const;

private:
    ByteView in_;
    std::size_t pos_ = 0;
};

// Проверка поддерживаемых версий; бросает UnsupportedVersion (§40 п.10:
// неподдерживаемая версия не интерпретируется эвристически).
template <std::size_t N>
std::array<std::uint8_t, N> ByteReader::fixed_array() {
    ByteView v = fixed(N);
    std::array<std::uint8_t, N> out{};
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

void require_supported(std::uint32_t format_version, std::uint32_t crypto_suite_id);

}  // namespace vault::encoding
