#pragma once
// EncryptedFileV1 (§14) — окончательный формат объекта с Milestone 1.
//   u32 format_version | u32 crypto_suite_id | 16 storage_uuid | 16 file_id
//   12 nonce | 40 wrapped_DEK | u64 ciphertext_length | N ciphertext | 16 gcm_tag

#include <cstdint>

#include "vault/common/bytes.hpp"

namespace vault::encoding {

struct EncryptedFileV1 {
    std::uint32_t format_version = kFormatVersionV1;
    std::uint32_t crypto_suite_id = kCryptoSuiteV1;
    StorageUuid storage_uuid{};
    FileId file_id{};
    Nonce nonce{};
    WrappedDek wrapped_dek{};
    Bytes ciphertext;  // без tag
    GcmTag gcm_tag{};
};

Bytes encode_encrypted_file(const EncryptedFileV1& obj);
// Строгий разбор + require_supported(). Привязку к storage_uuid проверяет
// вызывающая сторона (state verifier), т.к. парсер не знает TrustedState.
EncryptedFileV1 decode_encrypted_file(ByteView encoded);

// AAD (§10):
//   "edu-vault-file-v1" || u32 format_version || u32 crypto_suite_id
//   || 16 storage_uuid || 16 file_id
Bytes build_file_aad(std::uint32_t format_version, std::uint32_t crypto_suite_id,
                     const StorageUuid& storage_uuid, const FileId& file_id);

}  // namespace vault::encoding
