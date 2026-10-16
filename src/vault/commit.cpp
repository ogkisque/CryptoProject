// Crash-safe commit (§28-§29). Порядок шагов и crash-точки зафиксированы в
// docs/stages/03_rollback_crash_safety.md; TrustedState обновляется строго после durable publish.
#include "vault/vault/commit.hpp"

#include <algorithm>

#include "vault/common/error.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/encoding/manifest.hpp"
#include "vault/merkle/merkle.hpp"
#include "vault/storage/crash_injection.hpp"

namespace vault::core {

using storage::CrashPoint;
using storage::crash_here;

namespace {

struct SignedManifest {
    encoding::ManifestV1 manifest;
    Bytes encoded;
    Bytes signature;
};

// Подпись ML-DSA-65 hedged (docs/format_v1.md §8, решение S-1).
SignedManifest sign_manifest(const crypto::CryptoBackends& b, const encoding::ManifestV1& m, ByteView sig_sk) {
    SignedManifest out;
    out.manifest = m;
    out.encoded = encoding::encode_manifest(m);
    out.signature = b.sig->sign(sig_sk, out.encoded, label::kManifestSigContext, std::nullopt);
    return out;
}

}  // namespace

CommitProtocol::CommitProtocol(const crypto::CryptoBackends& backends, storage::IStorageBackend& storage,
                               storage::ITrustedStorage& trusted)
    : backends_(backends), storage_(storage), trusted_(trusted) {
    if (!backends.hash || !backends.merkle || !backends.sig)
        throw VaultError(ErrorCode::InvalidArgument, "commit: hash/merkle/sig backends are required");
}

CommitResult CommitProtocol::commit_initial(const StorageUuid& storage_uuid, ByteView kem_ct, ByteView kem_pk,
                                            const crypto::SigKeyPair& sig_keys) {
    CommitResult res;
    encoding::ManifestV1 m;
    m.storage_uuid = storage_uuid;
    m.generation = 0;
    m.file_count = 0;
    m.merkle_root = backends_.merkle->root_from_leaves({}, nullptr);  // EMPTY_ROOT
    m.kem_ct_hash = crypto::kem_ct_hash(*backends_.hash, kem_ct);
    m.kem_key_id = crypto::kem_key_id(*backends_.hash, kem_pk);
    m.sig_key_id = crypto::sig_key_id(*backends_.hash, sig_keys.public_key);
    SignedManifest sm = sign_manifest(backends_, m, sig_keys.secret_key.view());

    auto writer = storage_.begin_snapshot(0, std::nullopt);
    writer->put_manifest(sm.encoded, sm.signature);
    writer->sync();
    writer->publish();
    res.new_generation = 0;
    res.new_manifest_hash = crypto::manifest_hash(*backends_.hash, m);
    return res;
}

CommitResult CommitProtocol::commit(VerifiedState& current, const ChangeSet& changes) {
    CommitResult res;
    const std::uint64_t n = current.generation;

    // Предусловия: удаляемые есть, добавляемых нет, внутри набора повторов нет.
    auto has = [&](const FileId& id) {
        auto it = std::lower_bound(current.objects.begin(), current.objects.end(), id,
                                   [](const auto& o, const FileId& v) { return o.file_id < v; });
        return it != current.objects.end() && it->file_id == id;
    };
    for (const FileId& id : changes.removed)
        if (!has(id)) throw VaultError(ErrorCode::NotFound, "no such file_id");
    for (const auto& o : changes.added)
        if (has(o.file_id)) throw VaultError(ErrorCode::AlreadyExists, "file_id already exists");

    // 1. До начала записи
    crash_here(CrashPoint::BeforeSnapshotWrite);

    // Незавершённые и неподтверждённые поколения прежнего crash мешают номеру N+1.
    for (std::uint64_t g : storage_.list_generations())
        if (g > n) storage_.remove_generation(g);
    for (const std::string& t : storage_.list_incomplete_snapshots()) storage_.remove_incomplete_snapshot(t);

    // 2. Запись snapshot N+1
    std::vector<std::pair<FileId, Hash256>> entries;  // новый набор (file_id, leaf)
    entries.reserve(current.objects.size() + changes.added.size());
    {
        ScopedPhase p(&res.profile, Phase::Filesystem);
        auto writer = storage_.begin_snapshot(n + 1, n);
        bool crashed_during = false;
        auto after_first_op = [&] {
            if (!crashed_during) {
                crashed_during = true;
                crash_here(CrashPoint::DuringSnapshotWrite);
            }
        };
        std::vector<Bytes> encoded;
        encoded.reserve(changes.added.size());
        for (const auto& o : changes.added) {
            encoded.push_back(encoding::encode_encrypted_file(o));
            writer->put_object(o.file_id, encoded.back());
            after_first_op();
        }
        for (const FileId& id : changes.removed) {
            writer->remove_object(id);
            after_first_op();
        }

        // 3. Листья: для неизменённых объектов переиспользуем current.leaves
        {
            ScopedPhase pa(&res.profile, Phase::Algorithm);
            for (std::size_t i = 0; i < current.objects.size(); ++i) {
                const FileId& id = current.objects[i].file_id;
                if (std::find(changes.removed.begin(), changes.removed.end(), id) != changes.removed.end()) continue;
                entries.emplace_back(id, current.leaves[i]);
            }
            std::vector<ByteView> views(encoded.begin(), encoded.end());
            std::vector<Hash256> new_leaves(views.size());
            backends_.merkle->compute_leaves(views, new_leaves, nullptr);
            for (std::size_t i = 0; i < views.size(); ++i) entries.emplace_back(changes.added[i].file_id, new_leaves[i]);
            std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        }
        std::vector<Hash256> leaves;
        leaves.reserve(entries.size());
        for (const auto& e : entries) leaves.push_back(e.second);

        // 4. Manifest(N+1), подпись
        encoding::ManifestV1 m = current.manifest;
        m.generation = n + 1;
        m.file_count = leaves.size();
        SignedManifest sm;
        {
            ScopedPhase pa(&res.profile, Phase::Algorithm);
            m.merkle_root = backends_.merkle->root_from_leaves(leaves, nullptr);
            SecureBytes sig_sk = trusted_.load_sig_secret_key();
            sm = sign_manifest(backends_, m, sig_sk.view());
            res.new_manifest_hash = crypto::manifest_hash(*backends_.hash, m);
        }
        writer->put_manifest(sm.encoded, sm.signature);

        // 5. fsync -> publish
        writer->sync();
        crash_here(CrashPoint::AfterSnapshotFsync);
        writer->publish();
        crash_here(CrashPoint::AfterPublishBeforeTrusted);

        // 6. Доверенный anchor: именно здесь поколение N+1 становится «текущим»
        encoding::TrustedStateV1 ts = trusted_.load_state();
        ts.trusted_generation = n + 1;
        ts.trusted_manifest_hash = res.new_manifest_hash;
        trusted_.update_state(ts);
        crash_here(CrashPoint::AfterTrustedUpdate);

        // Успех: перенос нового состояния в current (без повторной проверки, §34).
        current.manifest = m;
        current.manifest_hash = res.new_manifest_hash;
        current.generation = n + 1;
        current.leaves = std::move(leaves);
    }
    std::erase_if(current.objects, [&](const auto& o) {
        return std::find(changes.removed.begin(), changes.removed.end(), o.file_id) != changes.removed.end();
    });
    for (const auto& o : changes.added) current.objects.push_back(o);
    std::sort(current.objects.begin(), current.objects.end(),
              [](const auto& a, const auto& b) { return a.file_id < b.file_id; });
    res.new_generation = n + 1;
    return res;
}

std::size_t CommitProtocol::garbage_collect() {
    const std::uint64_t keep = trusted_.load_state().trusted_generation;
    std::size_t removed = 0;
    for (std::uint64_t g : storage_.list_generations())
        if (g != keep) {
            storage_.remove_generation(g);
            ++removed;
        }
    for (const std::string& t : storage_.list_incomplete_snapshots()) {
        storage_.remove_incomplete_snapshot(t);
        ++removed;
    }
    return removed;
}

}  // namespace vault::core
