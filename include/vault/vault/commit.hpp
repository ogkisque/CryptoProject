#pragma once
// Crash-safe commit protocol (§28-§29):
//   verify(N) -> build snapshot N+1 (*.tmp) -> Merkle -> Manifest(N+1) -> Sign
//   -> write + fsync files + fsync dirs -> atomic publish -> fsync parent
//   -> atomic update TrustedState -> (отдельно) GC старых поколений.
// TrustedState обновляется строго после durable publish (§40 п.8).

#include <cstdint>
#include <vector>

#include "vault/common/bytes.hpp"
#include "vault/common/timing.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "vault/storage/storage_backend.hpp"
#include "vault/storage/trusted_storage.hpp"
#include "vault/vault/state_verifier.hpp"

namespace vault::core {

struct ChangeSet {
    std::vector<encoding::EncryptedFileV1> added;  // file_id уже проверены на уникальность
    std::vector<FileId> removed;
};

struct CommitResult {
    std::uint64_t new_generation = 0;
    Hash256 new_manifest_hash{};
    PhaseProfile profile;
};

class CommitProtocol {
public:
    CommitProtocol(const crypto::CryptoBackends& backends, storage::IStorageBackend& storage,
                   storage::ITrustedStorage& trusted);

    // current — результат StateVerifier на поколении N (§28 шаг 1).
    // Возвращает новое состояние; current после вызова устаревает.
    CommitResult commit(const VerifiedState& current, const ChangeSet& changes);

    // Начальное поколение 0 при vault init (§31).
    CommitResult commit_initial(const StorageUuid& storage_uuid, ByteView kem_ct);

    // Удалить все поколения < trusted_generation и orphan *.tmp. Возвращает число удалённых.
    std::size_t garbage_collect();

private:
    const crypto::CryptoBackends& backends_;
    storage::IStorageBackend& storage_;
    storage::ITrustedStorage& trusted_;
};

}  // namespace vault::core
