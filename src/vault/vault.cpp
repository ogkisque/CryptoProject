#include "vault/vault/vault.hpp"

#include <algorithm>

#include "vault/common/error.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "vault/encoding/manifest.hpp"
#include "vault/merkle/merkle.hpp"
#include "vault/storage/fs_util.hpp"
#include "vault/storage/storage_backend.hpp"
#include "vault/storage/trusted_storage.hpp"
#include "vault/vault/key_hierarchy.hpp"
#include "vault/vault/object_codec.hpp"

namespace vault {

namespace {

struct SignedManifest {
    encoding::ManifestV1 manifest;
    Bytes encoded;
    Bytes signature;
};

// Manifest по текущему набору листьев + подпись ML-DSA-65 (hedged, §8 решение S-1).
SignedManifest build_signed_manifest(const crypto::CryptoBackends& b, const StorageUuid& uuid, std::uint64_t generation,
                                     std::span<const Hash256> leaves, ByteView kem_ct, ByteView kem_pk,
                                     ByteView sig_pk, ByteView sig_sk) {
    SignedManifest out;
    encoding::ManifestV1& m = out.manifest;
    m.storage_uuid = uuid;
    m.generation = generation;
    m.file_count = leaves.size();
    m.merkle_root = b.merkle->root_from_leaves(leaves, nullptr);
    m.kem_ct_hash = crypto::kem_ct_hash(*b.hash, kem_ct);
    m.kem_key_id = crypto::kem_key_id(*b.hash, kem_pk);
    m.sig_key_id = crypto::sig_key_id(*b.hash, sig_pk);
    out.encoded = encoding::encode_manifest(m);
    out.signature = b.sig->sign(sig_sk, out.encoded, label::kManifestSigContext, std::nullopt);
    return out;
}

}  // namespace

struct Vault::Impl {
    VaultPaths paths;
    crypto::CryptoBackends backends;
    std::unique_ptr<storage::IStorageBackend> storage;
    std::unique_ptr<storage::ITrustedStorage> trusted;
    encoding::TrustedStateV1 trusted_state;
    core::VerifiedState verified;
    SecureBytes kek;  // живёт, пока открыт Vault; обнуляется деструктором

    // Пересобирает и подписывает Manifest для набора листьев, пишет его, затем sync+publish.
    void commit_manifest(storage::ISnapshotWriter& writer, std::span<const Hash256> leaves) {
        storage::TrustedPublicKeys pub = trusted->load_public_keys();
        if (!pub.sig_pk) throw VaultError(ErrorCode::NotFound, "trusted area has no signature public key");
        SecureBytes sig_sk = trusted->load_sig_secret_key();
        SignedManifest sm = build_signed_manifest(backends, trusted_state.storage_uuid, verified.generation, leaves,
                                                  verified.kem_ct, pub.kem_pk, *pub.sig_pk, sig_sk.view());
        writer.put_manifest(sm.encoded, sm.signature);
        writer.sync();
        writer.publish();
        verified.manifest = sm.manifest;
        verified.manifest_hash = crypto::manifest_hash(*backends.hash, sm.manifest);
    }

    std::vector<encoding::EncryptedFileV1>::iterator find(const FileId& id) {
        auto it = std::lower_bound(verified.objects.begin(), verified.objects.end(), id,
                                   [](const auto& o, const FileId& v) { return o.file_id < v; });
        if (it == verified.objects.end() || it->file_id != id) throw VaultError(ErrorCode::NotFound, "no such file_id");
        return it;
    }
};

Vault::Vault(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Vault::Vault(Vault&&) noexcept = default;
Vault& Vault::operator=(Vault&&) noexcept = default;
Vault::~Vault() = default;

void Vault::init(const VaultPaths& paths, const crypto::CryptoBackends& backends) {
    if (!backends.kem || !backends.random || !backends.hash || !backends.merkle || !backends.sig)
        throw VaultError(ErrorCode::InvalidArgument, "backends incomplete");
    auto storage = storage::make_flat_storage(paths.vault_dir);
    auto trusted = storage::make_file_trusted_storage(paths.trusted_dir);
    if (std::filesystem::exists(paths.vault_dir))
        throw VaultError(ErrorCode::AlreadyExists, "vault directory already exists: " + paths.vault_dir.string());
    if (std::filesystem::exists(paths.trusted_dir))
        throw VaultError(ErrorCode::AlreadyExists, "trusted directory already exists: " + paths.trusted_dir.string());

    encoding::TrustedStateV1 ts;
    backends.random->fill(MutableByteView(ts.storage_uuid));

    crypto::KemKeyPair kem = backends.kem->keygen(std::nullopt);
    core::InitialKeyMaterial km =
        core::establish_kek(*backends.kem, kem.public_key, ts.storage_uuid, ts.crypto_suite_id);
    // KEK на диске не хранится — обнуляется при выходе из функции.
    crypto::SigKeyPair sig = backends.sig->keygen(std::nullopt);

    // Пустой Manifest (root = EMPTY_ROOT) и его подпись.
    SignedManifest sm = build_signed_manifest(backends, ts.storage_uuid, 0, {}, km.ct_kem, kem.public_key,
                                              sig.public_key, sig.secret_key.view());

    storage->create_layout();
    storage->write_kem_ct(km.ct_kem);
    {
        auto w = storage->begin_snapshot(0, std::nullopt);
        w->put_manifest(sm.encoded, sm.signature);
        w->sync();
        w->publish();
    }
    // Доверенная область — последней: её наличие означает "init завершён".
    trusted->initialize(storage::TrustedKeys{kem.public_key, std::move(kem.secret_key), sig.public_key,
                                             std::move(sig.secret_key)},
                        ts);
}

Vault Vault::open(const VaultPaths& paths, crypto::CryptoBackends backends) {
    if (!backends.kem || !backends.random || !backends.hash || !backends.merkle || !backends.sig)
        throw VaultError(ErrorCode::InvalidArgument, "backends incomplete");
    auto impl = std::make_unique<Impl>();
    impl->paths = paths;
    impl->backends = std::move(backends);
    impl->storage = storage::make_flat_storage(paths.vault_dir);
    impl->trusted = storage::make_file_trusted_storage(paths.trusted_dir);
    if (!impl->trusted->exists())
        throw VaultError(ErrorCode::NotFound, "trusted state not found in " + paths.trusted_dir.string());
    if (!impl->storage->exists())
        throw VaultError(ErrorCode::NotFound, "vault directory not found: " + paths.vault_dir.string());

    core::StateVerifier verifier(impl->backends, *impl->storage, *impl->trusted);
    impl->verified = std::move(verifier.verify_current().state);
    impl->trusted_state = impl->trusted->load_state();

    // Только после успешной проверки состояния:
    SecureBytes sk = impl->trusted->load_kem_secret_key();
    impl->kek = core::recover_kek(*impl->backends.kem, sk.view(), impl->verified.kem_ct,
                                  impl->trusted_state.storage_uuid, impl->trusted_state.crypto_suite_id);
    return Vault(std::move(impl));
}

core::VerifyReport Vault::verify_state(const VaultPaths& paths, const crypto::CryptoBackends& backends) {
    auto storage = storage::make_flat_storage(paths.vault_dir);
    auto trusted = storage::make_file_trusted_storage(paths.trusted_dir);
    if (!trusted->exists())
        throw VaultError(ErrorCode::NotFound, "trusted state not found in " + paths.trusted_dir.string());
    if (!storage->exists()) throw VaultError(ErrorCode::NotFound, "vault directory not found: " + paths.vault_dir.string());
    return core::StateVerifier(backends, *storage, *trusted).verify_current();  // секреты не загружаются
}

FileId Vault::add_bytes(std::string_view filename, ByteView data) {
    FileId id{};
    do {
        impl_->backends.random->fill(MutableByteView(id));
    } while (std::any_of(impl_->verified.objects.begin(), impl_->verified.objects.end(),
                         [&](const auto& o) { return o.file_id == id; }));

    encoding::EncryptedFileV1 obj = core::encrypt_object(*impl_->backends.random, impl_->kek.view(),
                                                         impl_->trusted_state.storage_uuid, id, filename, data);
    Bytes encoded = encoding::encode_encrypted_file(obj);
    Hash256 leaf;
    {
        ByteView v(encoded);
        impl_->backends.merkle->compute_leaves(std::span<const ByteView>(&v, 1), std::span<Hash256>(&leaf, 1), nullptr);
    }
    auto pos = std::lower_bound(impl_->verified.objects.begin(), impl_->verified.objects.end(), id,
                                [](const auto& o, const FileId& v) { return o.file_id < v; });
    std::vector<Hash256> leaves = impl_->verified.leaves;
    leaves.insert(leaves.begin() + (pos - impl_->verified.objects.begin()), leaf);

    // M2: объект и Manifest пишутся по очереди без crash-safety (атомарный commit — этап 3).
    auto writer = impl_->storage->begin_snapshot(impl_->verified.generation, std::nullopt);
    writer->put_object(id, encoded);
    impl_->commit_manifest(*writer, leaves);

    impl_->verified.objects.insert(pos, std::move(obj));
    impl_->verified.leaves = std::move(leaves);
    return id;
}

FileId Vault::add_file(const std::filesystem::path& file) {
    SecureBytes data = storage::read_file_secure(file);
    std::string name = file.filename().string();
    return add_bytes(name, data.view());
}

ExtractedFile Vault::extract(const FileId& id) {
    auto it = impl_->find(id);
    encoding::FilePlaintext p = core::decrypt_object(impl_->kek.view(), *it);
    return ExtractedFile{std::move(p.filename), std::move(p.file_data)};
}

void Vault::remove(const FileId& id) {
    auto it = impl_->find(id);
    std::vector<Hash256> leaves = impl_->verified.leaves;
    leaves.erase(leaves.begin() + (it - impl_->verified.objects.begin()));
    auto writer = impl_->storage->begin_snapshot(impl_->verified.generation, std::nullopt);
    writer->remove_object(id);
    impl_->commit_manifest(*writer, leaves);
    impl_->verified.leaves = std::move(leaves);
    impl_->verified.objects.erase(it);
}

std::vector<ObjectInfo> Vault::list(bool decrypt_names) {
    std::vector<ObjectInfo> out;
    for (const auto& o : impl_->verified.objects) {
        ObjectInfo info;
        info.file_id = o.file_id;
        info.ciphertext_size = o.ciphertext.size();
        if (decrypt_names) info.filename = core::decrypt_object(impl_->kek.view(), o).filename;
        out.push_back(std::move(info));
    }
    return out;
}

core::VerifyReport Vault::verify() {
    core::StateVerifier verifier(impl_->backends, *impl_->storage, *impl_->trusted);
    core::VerifyReport report = verifier.verify_current();
    impl_->verified = report.state;
    return report;
}

std::size_t Vault::garbage_collect() { return 0; }  // этап 3

const core::VerifiedState& Vault::state() const { return impl_->verified; }

}  // namespace vault
