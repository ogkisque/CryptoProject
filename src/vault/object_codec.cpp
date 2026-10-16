#include "vault/vault/object_codec.hpp"

#include "vault/crypto/symmetric.hpp"

namespace vault::core {

encoding::EncryptedFileV1 encrypt_object(crypto::IRandom& rng, ByteView kek, const StorageUuid& storage_uuid,
                                         const FileId& file_id, std::string_view filename, ByteView file_data,
                                         PhaseProfile* profile) {
    // Каждый вызов — новый DEK; снаружи DEK передать нельзя (один DEK = одно шифрование).
    SecureBytes dek(kDekSize);
    encoding::EncryptedFileV1 obj;
    obj.storage_uuid = storage_uuid;
    obj.file_id = file_id;
    {
        ScopedPhase p(profile, Phase::Algorithm);
        rng.fill(dek.mutable_view());
        rng.fill(MutableByteView(obj.nonce));
    }

    SecureBytes plain;
    Bytes aad;
    {
        ScopedPhase p(profile, Phase::Serialization);
        plain = encoding::encode_file_plaintext(filename, file_data);
        aad = encoding::build_file_aad(obj.format_version, obj.crypto_suite_id, storage_uuid, file_id);
    }
    ScopedPhase p(profile, Phase::Algorithm);
    crypto::GcmCiphertext c = crypto::aes256_gcm_encrypt(dek.view(), obj.nonce, aad, plain.view());
    obj.ciphertext = std::move(c.ciphertext);
    obj.gcm_tag = c.tag;
    obj.wrapped_dek = crypto::aes256_kw_wrap(kek, dek.view());
    return obj;
}

encoding::FilePlaintext decrypt_object(ByteView kek, const encoding::EncryptedFileV1& obj, PhaseProfile* profile) {
    SecureBytes plain;
    {
        ScopedPhase p(profile, Phase::Algorithm);
        SecureBytes dek = crypto::aes256_kw_unwrap(kek, obj.wrapped_dek);
        Bytes aad = encoding::build_file_aad(obj.format_version, obj.crypto_suite_id, obj.storage_uuid, obj.file_id);
        plain = crypto::aes256_gcm_decrypt(dek.view(), obj.nonce, aad, obj.ciphertext, obj.gcm_tag);
    }
    ScopedPhase p(profile, Phase::Serialization);
    return encoding::decode_file_plaintext(plain.view());
}

}  // namespace vault::core
