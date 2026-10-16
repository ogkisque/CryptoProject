#include "vault/vault/vault.hpp"

#include <algorithm>

#include "vault/common/error.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "vault/storage/fs_util.hpp"
#include "vault/storage/storage_backend.hpp"
#include "vault/storage/trusted_storage.hpp"
#include "vault/vault/key_hierarchy.hpp"
#include "vault/vault/object_codec.hpp"

namespace vault {

struct Vault::Impl {
    VaultPaths paths;
    crypto::CryptoBackends backends;
    std::unique_ptr<storage::IStorageBackend> storage;
    std::unique_ptr<storage::ITrustedStorage> trusted;
    encoding::TrustedStateV1 trusted_state;
    core::VerifiedState verified;
    SecureBytes kek;  // живёт, пока открыт Vault; обнуляется деструктором

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
    if (!backends.kem || !backends.random) throw VaultError(ErrorCode::InvalidArgument, "backends incomplete");
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

    storage->create_layout();
    storage->write_kem_ct(km.ct_kem);
    // Доверенная область — последней: её наличие означает "init завершён".
    trusted->initialize(storage::TrustedKeys{kem.public_key, std::move(kem.secret_key), std::nullopt, std::nullopt}, ts);
}

Vault Vault::open(const VaultPaths& paths, crypto::CryptoBackends backends) {
    if (!backends.kem || !backends.random || !backends.hash)
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

FileId Vault::add_bytes(std::string_view filename, ByteView data) {
    FileId id{};
    do {
        impl_->backends.random->fill(MutableByteView(id));
    } while (std::any_of(impl_->verified.objects.begin(), impl_->verified.objects.end(),
                         [&](const auto& o) { return o.file_id == id; }));

    encoding::EncryptedFileV1 obj = core::encrypt_object(*impl_->backends.random, impl_->kek.view(),
                                                         impl_->trusted_state.storage_uuid, id, filename, data);
    auto writer = impl_->storage->begin_snapshot(impl_->verified.generation, std::nullopt);
    writer->put_object(id, encoding::encode_encrypted_file(obj));
    writer->sync();
    writer->publish();

    auto pos = std::lower_bound(impl_->verified.objects.begin(), impl_->verified.objects.end(), id,
                                [](const auto& o, const FileId& v) { return o.file_id < v; });
    impl_->verified.objects.insert(pos, std::move(obj));
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
    auto writer = impl_->storage->begin_snapshot(impl_->verified.generation, std::nullopt);
    writer->remove_object(id);
    writer->sync();
    writer->publish();
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
