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

    // current — результат StateVerifier на поколении N == trusted_generation (§28 шаг 1).
    // Если trusted state уже указывает на другое состояние (current устарел), бросает
    // VaultError(StateVerification) и ничего не трогает на диске.
    // При успехе current обновляется на месте до состояния N+1 (повторная проверка не нужна, §34);
    // при исключении current не меняется. Вызывающий обязан держать блокировку хранилища.
    // Осиротевшие поколения > N и *.tmp (след прежнего crash) перед записью удаляются:
    // они не подтверждены trusted state, а их номер понадобится новому поколению.
    CommitResult commit(VerifiedState& current, const ChangeSet& changes);

    // Начальное поколение 0 при vault init (§31): публикует пустой подписанный Manifest.
    // TrustedState здесь НЕ трогается — его создаёт init последним (по manifest_hash из результата).
    // Ключи передаются явно: доверенной области ещё нет.
    CommitResult commit_initial(const StorageUuid& storage_uuid, ByteView kem_ct, ByteView kem_pk,
                                const crypto::SigKeyPair& sig_keys);

    // Удалить все поколения != trusted_generation (старые и осиротевшие новее trusted) и все *.tmp.
    // Возвращает число удалённых. Вызывается только явно (`vault gc`), никогда из commit.
    std::size_t garbage_collect();

private:
    const crypto::CryptoBackends& backends_;
    storage::IStorageBackend& storage_;
    storage::ITrustedStorage& trusted_;
};

}  // namespace vault::core
