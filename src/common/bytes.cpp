#include "vault/common/bytes.hpp"

#include <openssl/crypto.h>

namespace vault {

std::string to_hex(ByteView data) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t b : data) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0f]);
    }
    return out;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<Bytes> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    Bytes out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_value(hex[i]);
        int lo = hex_value(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::optional<FileId> file_id_from_hex(std::string_view hex) {
    if (hex.size() != kFileIdSize * 2) return std::nullopt;
    auto bytes = from_hex(hex);
    if (!bytes) return std::nullopt;
    FileId id{};
    std::copy(bytes->begin(), bytes->end(), id.begin());
    return id;
}

bool constant_time_equal(ByteView a, ByteView b) noexcept {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace vault
