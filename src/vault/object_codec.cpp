#include "vault/vault/object_codec.hpp"

#include "vault/crypto/symmetric.hpp"

namespace vault::core {

encoding::EncryptedFileV1 encrypt_object(crypto::IRandom& rng, ByteView kek, const StorageUuid& storage_uuid,
                                         const FileId& file_id, std::string_view filename, ByteView file_data) {
    // Каждый вызов — новый DEK; снаружи DEK передать нельзя (один DEK = одно шифрование).
    SecureBytes dek(kDekSize);
    rng.fill(dek.mutable_view());

    encoding::EncryptedFileV1 obj;
    obj.storage_uuid = storage_uuid;
    obj.file_id = file_id;
    rng.fill(MutableByteView(obj.nonce));

    SecureBytes plain = encoding::encode_file_plaintext(filename, file_data);
    Bytes aad = encoding::build_file_aad(obj.format_version, obj.crypto_suite_id, storage_uuid, file_id);
    crypto::GcmCiphertext c = crypto::aes256_gcm_encrypt(dek.view(), obj.nonce, aad, plain.view());
    obj.ciphertext = std::move(c.ciphertext);
    obj.gcm_tag = c.tag;
    obj.wrapped_dek = crypto::aes256_kw_wrap(kek, dek.view());
    return obj;
}

encoding::FilePlaintext decrypt_object(ByteView kek, const encoding::EncryptedFileV1& obj) {
    SecureBytes dek = crypto::aes256_kw_unwrap(kek, obj.wrapped_dek);
    Bytes aad = encoding::build_file_aad(obj.format_version, obj.crypto_suite_id, obj.storage_uuid, obj.file_id);
    SecureBytes plain = crypto::aes256_gcm_decrypt(dek.view(), obj.nonce, aad, obj.ciphertext, obj.gcm_tag);
    return encoding::decode_file_plaintext(plain.view());
}

}  // namespace vault::core
