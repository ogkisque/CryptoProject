#include "vault/encoding/canonical.hpp"

#include "vault/common/error.hpp"

namespace vault::encoding {

namespace {
[[noreturn]] void format_error(const char* what) {
    throw VaultError(ErrorCode::FormatError, what);
}
}  // namespace

ByteWriter::ByteWriter(std::size_t reserve) { out_.reserve(reserve); }

void ByteWriter::u8(std::uint8_t v) { out_.push_back(v); }

void ByteWriter::u32(std::uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) out_.push_back(static_cast<std::uint8_t>(v >> shift));
}

void ByteWriter::u64(std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) out_.push_back(static_cast<std::uint8_t>(v >> shift));
}

void ByteWriter::fixed(ByteView data) { out_.insert(out_.end(), data.begin(), data.end()); }

void ByteWriter::var_u32(ByteView data) {
    if (data.size() > UINT32_MAX) format_error("var_u32: data too long");
    u32(static_cast<std::uint32_t>(data.size()));
    fixed(data);
}

void ByteWriter::var_u64(ByteView data) {
    u64(static_cast<std::uint64_t>(data.size()));
    fixed(data);
}

std::uint8_t ByteReader::u8() { return fixed(1)[0]; }

std::uint32_t ByteReader::u32() {
    ByteView v = fixed(4);
    std::uint32_t r = 0;
    for (auto b : v) r = (r << 8) | b;
    return r;
}

std::uint64_t ByteReader::u64() {
    ByteView v = fixed(8);
    std::uint64_t r = 0;
    for (auto b : v) r = (r << 8) | b;
    return r;
}

ByteView ByteReader::fixed(std::size_t n) {
    if (n > remaining()) format_error("unexpected end of data");
    ByteView v = in_.subspan(pos_, n);
    pos_ += n;
    return v;
}

ByteView ByteReader::var_u32(std::uint32_t max_len) {
    std::uint32_t len = u32();
    if (len > max_len || len > remaining()) format_error("invalid field length");
    return fixed(len);
}

ByteView ByteReader::var_u64(std::uint64_t max_len) {
    std::uint64_t len = u64();
    if (len > max_len || len > remaining()) format_error("invalid field length");
    return fixed(static_cast<std::size_t>(len));
}

void ByteReader::expect_end() const {
    if (remaining() != 0) format_error("trailing data");
}

void require_supported(std::uint32_t format_version, std::uint32_t crypto_suite_id) {
    if (format_version != kFormatVersionV1)
        throw VaultError(ErrorCode::UnsupportedVersion, "unsupported format_version");
    if (crypto_suite_id != kCryptoSuiteV1)
        throw VaultError(ErrorCode::UnsupportedVersion, "unsupported crypto_suite_id");
}

}  // namespace vault::encoding
