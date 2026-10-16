#include "vault/vault/key_hierarchy.hpp"

#include "vault/crypto/symmetric.hpp"
#include "vault/encoding/canonical.hpp"

namespace vault::core {

SecureBytes derive_kek(ByteView k_mlkem, const StorageUuid& storage_uuid, std::uint32_t crypto_suite_id) {
    encoding::ByteWriter info(label::kKekInfo.size() + 4);
    info.fixed(as_view(label::kKekInfo));
    info.u32(crypto_suite_id);
    return crypto::hkdf_sha3_256(k_mlkem, as_view(storage_uuid), info.bytes(), kKekSize);
}

InitialKeyMaterial establish_kek(crypto::IKemBackend& kem, ByteView pk_kem, const StorageUuid& storage_uuid,
                                 std::uint32_t crypto_suite_id) {
    crypto::KemEncapsResult r = kem.encaps(pk_kem, std::nullopt);
    SecureBytes kek = derive_kek(r.shared_secret.view(), storage_uuid, crypto_suite_id);
    return InitialKeyMaterial{std::move(r.ciphertext), std::move(kek)};  // shared_secret обнуляется деструктором
}

SecureBytes recover_kek(crypto::IKemBackend& kem, ByteView sk_kem, ByteView ct_kem,
                        const StorageUuid& storage_uuid, std::uint32_t crypto_suite_id) {
    SecureBytes k = kem.decaps(sk_kem, ct_kem);
    return derive_kek(k.view(), storage_uuid, crypto_suite_id);
}

}  // namespace vault::core
