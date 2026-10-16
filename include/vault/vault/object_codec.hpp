#pragma once
// Шифрование/расшифрование одного объекта (§8-§15).

#include <string_view>

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"
#include "vault/common/timing.hpp"
#include "vault/crypto/random.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "vault/encoding/file_plaintext.hpp"

namespace vault::core {

// profile (необязательный): Algorithm — AES-GCM/KW и RNG, Serialization — (де)кодирование FilePlaintext.
// Генерирует новый DEK и nonce (каждый вызов — новый DEK, §8),
// шифрует CanonicalEncode(FilePlaintext) с AAD, оборачивает DEK через KEK.
// DEK обнуляется до выхода.
encoding::EncryptedFileV1 encrypt_object(crypto::IRandom& rng, ByteView kek,
                                         const StorageUuid& storage_uuid, const FileId& file_id,
                                         std::string_view filename, ByteView file_data,
                                         PhaseProfile* profile = nullptr);

// AES-KW unwrap -> AES-GCM decrypt+verify -> decode FilePlaintext.
// Любая ошибка -> исключение, plaintext не возвращается (§53).
encoding::FilePlaintext decrypt_object(ByteView kek, const encoding::EncryptedFileV1& obj,
                                       PhaseProfile* profile = nullptr);

}  // namespace vault::core
