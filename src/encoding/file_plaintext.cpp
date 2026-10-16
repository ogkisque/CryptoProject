#include "vault/encoding/file_plaintext.hpp"

#include <limits>

#include "vault/common/error.hpp"
#include "vault/encoding/canonical.hpp"

namespace vault::encoding {

namespace {

// Строгая проверка UTF-8 (RFC 3629): без overlong, суррогатов и > U+10FFFF.
bool is_valid_utf8(std::string_view s) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    std::size_t n = s.size(), i = 0;
    while (i < n) {
        unsigned char c = p[i];
        if (c < 0x80) { ++i; continue; }
        std::size_t len;
        std::uint32_t cp;
        if (c >= 0xC2 && c <= 0xDF) { len = 2; cp = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { len = 3; cp = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { len = 4; cp = c & 0x07; }
        else return false;
        if (i + len > n) return false;
        for (std::size_t k = 1; k < len; ++k) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if (len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) return false;
        if (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) return false;
        i += len;
    }
    return true;
}

void put_be(std::uint8_t* out, std::uint64_t v, int bytes) {
    for (int i = 0; i < bytes; ++i) out[i] = static_cast<std::uint8_t>(v >> (8 * (bytes - 1 - i)));
}

}  // namespace

SecureBytes encode_file_plaintext(std::string_view filename, ByteView file_data) {
    if (filename.empty() || filename.size() > kMaxFilenameLength)
        throw VaultError(ErrorCode::InvalidArgument, "invalid filename length");
    if (!is_valid_utf8(filename))
        throw VaultError(ErrorCode::InvalidArgument, "filename is not valid UTF-8");
    // Собираем сразу в SecureBytes известного размера: промежуточных копий plaintext нет.
    SecureBytes out(4 + filename.size() + 8 + file_data.size());
    std::uint8_t* p = out.data();
    put_be(p, filename.size(), 4);
    p += 4;
    std::copy(filename.begin(), filename.end(), p);
    p += filename.size();
    put_be(p, file_data.size(), 8);
    p += 8;
    std::copy(file_data.begin(), file_data.end(), p);
    return out;
}

FilePlaintext decode_file_plaintext(ByteView encoded) {
    ByteReader r(encoded);
    ByteView name = r.var_u32(kMaxFilenameLength);
    if (name.empty()) throw VaultError(ErrorCode::FormatError, "empty filename");
    std::string filename(reinterpret_cast<const char*>(name.data()), name.size());
    if (!is_valid_utf8(filename)) throw VaultError(ErrorCode::FormatError, "filename is not valid UTF-8");
    ByteView data = r.var_u64(std::numeric_limits<std::uint64_t>::max());
    r.expect_end();
    return FilePlaintext{std::move(filename), SecureBytes(data)};
}

}  // namespace vault::encoding
