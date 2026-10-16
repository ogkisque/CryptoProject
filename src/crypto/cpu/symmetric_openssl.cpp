#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <algorithm>
#include <cstdint>
#include <memory>

#include "vault/common/error.hpp"
#include "vault/crypto/symmetric.hpp"

namespace vault::crypto {

namespace {

struct CtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

CtxPtr new_ctx() {
    CtxPtr c(EVP_CIPHER_CTX_new());
    if (!c) throw VaultError(ErrorCode::CryptoError, "EVP_CIPHER_CTX_new failed");
    return c;
}

[[noreturn]] void crypto_fail(const char* what) { throw VaultError(ErrorCode::CryptoError, what); }

int to_int(std::size_t n) {
    if (n > 0x7fffffffu) crypto_fail("input too large for OpenSSL EVP int length");
    return static_cast<int>(n);
}

// EVP_*Update принимает int — большие файлы обрабатываются порциями.
constexpr std::size_t kChunk = std::size_t{1} << 30;

template <class UpdateFn>
std::size_t update_chunked(UpdateFn update, std::uint8_t* out, ByteView in) {
    std::size_t total = 0;
    for (std::size_t off = 0; off < in.size(); off += kChunk) {
        std::size_t n = std::min(kChunk, in.size() - off);
        int len = 0;
        if (update(out + total, &len, in.data() + off, static_cast<int>(n)) != 1) return SIZE_MAX;
        total += static_cast<std::size_t>(len);
    }
    return total;
}

}  // namespace

GcmCiphertext aes256_gcm_encrypt(ByteView key, const Nonce& nonce, ByteView aad, ByteView plaintext) {
    if (key.size() != 32) throw VaultError(ErrorCode::InvalidArgument, "AES-256 key must be 32 bytes");
    CtxPtr ctx = new_ctx();
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kNonceSize, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        crypto_fail("GCM init failed");
    int len = 0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), to_int(aad.size())) != 1)
        crypto_fail("GCM AAD failed");
    GcmCiphertext out;
    out.ciphertext.resize(plaintext.size());
    std::size_t total = update_chunked(
        [&](std::uint8_t* o, int* l, const std::uint8_t* i, int n) { return EVP_EncryptUpdate(ctx.get(), o, l, i, n); },
        out.ciphertext.data(), plaintext);
    if (total == SIZE_MAX) crypto_fail("GCM encrypt failed");
    std::uint8_t dummy[16];
    if (EVP_EncryptFinal_ex(ctx.get(), dummy, &len) != 1) crypto_fail("GCM final failed");
    if (total != plaintext.size()) crypto_fail("GCM length mismatch");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagSize, out.tag.data()) != 1)
        crypto_fail("GCM get tag failed");
    return out;
}

SecureBytes aes256_gcm_decrypt(ByteView key, const Nonce& nonce, ByteView aad, ByteView ciphertext,
                               const GcmTag& tag) {
    if (key.size() != 32) throw VaultError(ErrorCode::InvalidArgument, "AES-256 key must be 32 bytes");
    CtxPtr ctx = new_ctx();
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kNonceSize, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        crypto_fail("GCM init failed");
    int len = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), to_int(aad.size())) != 1)
        crypto_fail("GCM AAD failed");
    // Расшифровываем во внутренний SecureBytes; наружу он уходит только после проверки tag.
    SecureBytes plain(ciphertext.size());
    std::size_t total = update_chunked(
        [&](std::uint8_t* o, int* l, const std::uint8_t* i, int n) { return EVP_DecryptUpdate(ctx.get(), o, l, i, n); },
        plain.data(), ciphertext);
    if (total == SIZE_MAX) {
        plain.wipe();
        crypto_fail("GCM decrypt failed");
    }
    GcmTag tag_copy = tag;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagSize, tag_copy.data()) != 1)
        crypto_fail("GCM set tag failed");
    std::uint8_t dummy[16];
    if (EVP_DecryptFinal_ex(ctx.get(), dummy, &len) != 1) {
        plain.wipe();
        throw VaultError(ErrorCode::AuthenticationFailed, "AES-GCM authentication failed");
    }
    if (total != ciphertext.size()) {
        plain.wipe();
        crypto_fail("GCM length mismatch");
    }
    return plain;
}

WrappedDek aes256_kw_wrap(ByteView kek, ByteView dek) {
    if (kek.size() != 32 || dek.size() != kDekSize)
        throw VaultError(ErrorCode::InvalidArgument, "AES-KW: KEK and DEK must be 32 bytes");
    CtxPtr ctx = new_ctx();
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_wrap(), nullptr, kek.data(), nullptr) != 1)
        crypto_fail("AES-KW init failed");
    WrappedDek out{};
    int len = 0;
    if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, dek.data(), to_int(dek.size())) != 1 ||
        static_cast<std::size_t>(len) != kWrappedDekSize)
        crypto_fail("AES-KW wrap failed");
    int fin = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + len, &fin) != 1 || fin != 0)
        crypto_fail("AES-KW final failed");
    return out;
}

SecureBytes aes256_kw_unwrap(ByteView kek, const WrappedDek& wrapped) {
    if (kek.size() != 32) throw VaultError(ErrorCode::InvalidArgument, "AES-KW: KEK must be 32 bytes");
    CtxPtr ctx = new_ctx();
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_wrap(), nullptr, kek.data(), nullptr) != 1)
        crypto_fail("AES-KW init failed");
    SecureBytes out(kWrappedDekSize);  // с запасом; фактическая длина — kDekSize
    int len = 0;
    if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, wrapped.data(), to_int(wrapped.size())) != 1 ||
        static_cast<std::size_t>(len) != kDekSize) {
        out.wipe();
        throw VaultError(ErrorCode::AuthenticationFailed, "AES-KW integrity check failed");
    }
    SecureBytes dek(ByteView(out.data(), kDekSize));
    out.wipe();
    return dek;
}

SecureBytes hkdf_sha3_256(ByteView ikm, ByteView salt, ByteView info, std::size_t out_len) {
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
    if (!kdf) crypto_fail("HKDF not available");
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
    if (!ctx) crypto_fail("EVP_KDF_CTX_new failed");
    char digest[] = "SHA3-256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(ikm.data()), ikm.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<std::uint8_t*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()};
    SecureBytes out(out_len);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1) crypto_fail("HKDF derive failed");
    return out;
}

}  // namespace vault::crypto
