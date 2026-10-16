#include "vault/common/secure_buffer.hpp"

#include <openssl/crypto.h>

#include <utility>

namespace vault {

void secure_zero(void* ptr, std::size_t len) noexcept {
    if (ptr && len) OPENSSL_cleanse(ptr, len);
}

SecureBytes::SecureBytes(std::size_t size) : buf_(size, 0) {}

SecureBytes::SecureBytes(ByteView data) : buf_(data.begin(), data.end()) {}

SecureBytes::~SecureBytes() { wipe(); }

SecureBytes::SecureBytes(SecureBytes&& other) noexcept : buf_(std::move(other.buf_)) {
    other.buf_.clear();
}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
    if (this != &other) {
        wipe();
        buf_ = std::move(other.buf_);
        other.buf_.clear();
    }
    return *this;
}

SecureBytes SecureBytes::clone() const { return SecureBytes(view()); }

void SecureBytes::wipe() noexcept {
    secure_zero(buf_.data(), buf_.size());
    std::vector<std::uint8_t>().swap(buf_);
}

}  // namespace vault
