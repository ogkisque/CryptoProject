#pragma once
// Симметричные примитивы — только CPU (OpenSSL 3), §41: AES-GCM, AES-KW и KDF
// на GPU не переносятся.

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"

namespace vault::crypto {

struct GcmCiphertext {
    Bytes ciphertext;
    GcmTag tag{};
};

// AES-256-GCM, nonce 96 bit, tag 128 bit.
GcmCiphertext aes256_gcm_encrypt(ByteView key, const Nonce& nonce, ByteView aad,
                                 ByteView plaintext);
// Plaintext возвращается ТОЛЬКО после успешной проверки tag; иначе
// VaultError(AuthenticationFailed), промежуточный буфер обнуляется (§40 п.9).
SecureBytes aes256_gcm_decrypt(ByteView key, const Nonce& nonce, ByteView aad,
                               ByteView ciphertext, const GcmTag& tag);

// AES-256-KW (RFC 3394 / NIST SP 800-38F, IV по умолчанию A6A6...).
WrappedDek aes256_kw_wrap(ByteView kek, ByteView dek);
// Ошибка integrity check -> VaultError(AuthenticationFailed).
SecureBytes aes256_kw_unwrap(ByteView kek, const WrappedDek& wrapped);

// HKDF (RFC 5869) с SHA3-256.
SecureBytes hkdf_sha3_256(ByteView ikm, ByteView salt, ByteView info, std::size_t out_len);

}  // namespace vault::crypto
