#pragma once
// Полная проверка текущего состояния хранилища (§27, §52).
// Порядок шагов фиксирован: дорогие/секретные операции (Decaps) возможны
// только после успеха ВСЕХ шагов. Ошибка -> VerificationError(step).
//
// Объём проверки растёт по milestone'ам:
//   M1: разбор объектов, привязка к storage_uuid/version/suite, уникальность file_id.
//   M2: + Manifest, ML-DSA, key ids, kem_ct_hash, file_count, Merkle root.
//   M3: + generation == trusted_generation, manifest_hash == trusted_manifest_hash.

#include <cstdint>
#include <vector>

#include "vault/common/bytes.hpp"
#include "vault/common/timing.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "vault/encoding/manifest.hpp"
#include "vault/encoding/trusted_state.hpp"
#include "vault/storage/storage_backend.hpp"
#include "vault/storage/trusted_storage.hpp"

namespace vault::core {

// Состояние, прошедшее проверку. Только из него разрешено читать/менять данные.
struct VerifiedState {
    std::uint64_t generation = 0;
    encoding::ManifestV1 manifest;  // M2+
    Hash256 manifest_hash{};        // M3+
    Bytes kem_ct;                   // сверен с manifest.kem_ct_hash (M2+)
    std::vector<encoding::EncryptedFileV1> objects;  // отсортированы по file_id
    std::vector<Hash256> leaves;                     // в том же порядке
};

struct VerifyReport {
    VerifiedState state;
    PhaseProfile profile;          // algorithm / serialization / fs / memcpy
    TimingBreakdown merkle_timing;  // от merkle backend
};

class StateVerifier {
public:
    StateVerifier(const crypto::CryptoBackends& backends, const storage::IStorageBackend& storage,
                  const storage::ITrustedStorage& trusted);

    // Бросает VerificationError с шагом, на котором обнаружено нарушение.
    VerifyReport verify_current() const;

private:
    const crypto::CryptoBackends& backends_;
    const storage::IStorageBackend& storage_;
    const storage::ITrustedStorage& trusted_;
};

}  // namespace vault::core
