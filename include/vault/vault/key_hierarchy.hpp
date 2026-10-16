#pragma once
// Иерархия ключей (§6, §7, §11):
//   SK_KEM + CT_KEM --Decaps--> K_MLKEM --HKDF-SHA3-256--> KEK --AES-KW--> DEK_i

#include <cstdint>

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"
#include "vault/crypto/kem_backend.hpp"

namespace vault::core {

// KEK = HKDF-SHA3-256(IKM = K_MLKEM, salt = storage_uuid,
//                     info = "edu-vault-kek-v1" || u32 crypto_suite_id, L = 32)
SecureBytes derive_kek(ByteView k_mlkem, const StorageUuid& storage_uuid,
                       std::uint32_t crypto_suite_id);

struct InitialKeyMaterial {
    Bytes ct_kem;     // сохраняется в недоверенном хранилище
    SecureBytes kek;  // только в RAM
};

// vault init: Encaps(PK_KEM) -> (CT_KEM, K_MLKEM) -> KEK. K_MLKEM обнуляется внутри.
InitialKeyMaterial establish_kek(crypto::IKemBackend& kem, ByteView pk_kem,
                                 const StorageUuid& storage_uuid, std::uint32_t crypto_suite_id);

// Восстановление KEK. ПРЕДУСЛОВИЕ (M2+): ct_kem уже сверен с Manifest.kem_ct_hash.
SecureBytes recover_kek(crypto::IKemBackend& kem, ByteView sk_kem, ByteView ct_kem,
                        const StorageUuid& storage_uuid, std::uint32_t crypto_suite_id);

}  // namespace vault::core
