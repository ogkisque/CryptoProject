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
#include "vault/vault/commit.hpp"
#include "vault/vault/key_hierarchy.hpp"
#include "vault/vault/object_codec.hpp"

namespace vault {

namespace {

// Единственное место выбора реализации хранилищ.
std::unique_ptr<storage::IStorageBackend> make_storage(const VaultPaths& p) {
    return storage::make_generation_storage(p.vault_dir);
}
std::unique_ptr<storage::ITrustedStorage> make_trusted(const VaultPaths& p) {
    return storage::make_file_trusted_storage(p.trusted_dir);
}

}  // namespace

struct Vault::Impl {
    VaultPaths paths;
    crypto::CryptoBackends backends;
    std::unique_ptr<storage::IStorageBackend> storage;
    std::unique_ptr<storage::ITrustedStorage> trusted;
    encoding::TrustedStateV1 trusted_state;
    core::VerifiedState verified;
    PhaseProfile open_profile, last_profile;
    SecureBytes kek;  // живёт, пока открыт Vault; обнуляется деструктором

    // Транзакция (§3.3a): эксклюзивная блокировка на время «актуализация состояния -> commit».
    // Если другой процесс успел сделать commit с момента нашей проверки (trusted state ушёл вперёд),
    // состояние перечитывается и перепроверяется — иначе два параллельных `add` построили бы
    // два разных поколения N+1.
    template <typename Fn>
    void transaction(Fn&& fn) {
        storage::FileLock lock(paths.vault_dir / ".lock");
        encoding::TrustedStateV1 ts = trusted->load_state();
        if (!(ts == trusted_state)) {
            core::VerifyReport r = core::StateVerifier(backends, *storage, *trusted).verify_current();
            verified = std::move(r.state);
            trusted_state = r.trusted_state;
        }
        fn();
        trusted_state = trusted->load_state();
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
    auto storage = make_storage(paths);
    auto trusted = make_trusted(paths);
    if (std::filesystem::exists(paths.vault_dir))
        throw VaultError(ErrorCode::AlreadyExists,
                         "vault directory already exists: " + paths.vault_dir.string() +
                             (std::filesystem::exists(paths.trusted_dir)
                                  ? ""
                                  : " (no trusted area: incomplete initialization? remove the directory and retry)"));
    if (std::filesystem::exists(paths.trusted_dir))
        throw VaultError(ErrorCode::AlreadyExists, "trusted directory already exists: " + paths.trusted_dir.string());

    encoding::TrustedStateV1 ts;
    backends.random->fill(MutableByteView(ts.storage_uuid));

    crypto::KemKeyPair kem = backends.kem->keygen(std::nullopt);
    core::InitialKeyMaterial km =
        core::establish_kek(*backends.kem, kem.public_key, ts.storage_uuid, ts.crypto_suite_id);
    // KEK на диске не хранится — обнуляется при выходе из функции.
    crypto::SigKeyPair sig = backends.sig->keygen(std::nullopt);

    // Порядок init: vault/ (kem.ct, поколение 0) -> доверенная область ПОСЛЕДНЕЙ. Наличие trusted
    // state означает «init завершён». Если процесс убит посередине, остаётся vault/ без trusted/:
    // повторный init сообщит о неполной инициализации, каталог нужно удалить вручную.
    // При обычной ошибке (исключении) откатывается только то, что создал этот вызов:
    // если каталог успел создать кто-то другой (AlreadyExists), его трогать нельзя.
    bool vault_created = false, trusted_created = false;
    try {
        storage->create_layout();
        vault_created = true;
        storage->write_kem_ct(km.ct_kem);
        core::CommitProtocol commit(backends, *storage, *trusted);
        core::CommitResult gen0 = commit.commit_initial(ts.storage_uuid, km.ct_kem, kem.public_key, sig);
        ts.trusted_generation = 0;
        ts.trusted_manifest_hash = gen0.new_manifest_hash;
        try {
            trusted->initialize(storage::TrustedKeys{kem.public_key, std::move(kem.secret_key), sig.public_key,
                                                     std::move(sig.secret_key)},
                                ts);
        } catch (const VaultError& e) {
            trusted_created = e.code() != ErrorCode::AlreadyExists;  // initialize успел что-то создать
            throw;
        } catch (...) {
            trusted_created = true;
            throw;
        }
    } catch (...) {
        std::error_code ec;
        if (vault_created) std::filesystem::remove_all(paths.vault_dir, ec);
        if (trusted_created) std::filesystem::remove_all(paths.trusted_dir, ec);
        throw;
    }
}

Vault Vault::open(const VaultPaths& paths, crypto::CryptoBackends backends) {
    if (!backends.kem || !backends.random || !backends.hash || !backends.merkle || !backends.sig)
        throw VaultError(ErrorCode::InvalidArgument, "backends incomplete");
    auto impl = std::make_unique<Impl>();
    impl->paths = paths;
    impl->backends = std::move(backends);
    impl->storage = make_storage(paths);
    impl->trusted = make_trusted(paths);
    if (!impl->trusted->exists())
        throw VaultError(ErrorCode::NotFound, "trusted state not found in " + paths.trusted_dir.string());
    if (!impl->storage->exists())
        throw VaultError(ErrorCode::NotFound, "vault directory not found: " + paths.vault_dir.string());

    core::VerifyReport report = core::StateVerifier(impl->backends, *impl->storage, *impl->trusted).verify_current();
    impl->verified = std::move(report.state);
    impl->open_profile = report.profile;
    impl->trusted_state = report.trusted_state;  // не перечитывать: см. VerifyReport::trusted_state

    // Только после успешной проверки состояния:
    SecureBytes sk = impl->trusted->load_kem_secret_key();
    impl->kek = core::recover_kek(*impl->backends.kem, sk.view(), impl->verified.kem_ct,
                                  impl->trusted_state.storage_uuid, impl->trusted_state.crypto_suite_id);
    return Vault(std::move(impl));
}

core::VerifyReport Vault::verify_state(const VaultPaths& paths, const crypto::CryptoBackends& backends) {
    auto storage = make_storage(paths);
    auto trusted = make_trusted(paths);
    if (!trusted->exists())
        throw VaultError(ErrorCode::NotFound, "trusted state not found in " + paths.trusted_dir.string());
    if (!storage->exists()) throw VaultError(ErrorCode::NotFound, "vault directory not found: " + paths.vault_dir.string());
    return core::StateVerifier(backends, *storage, *trusted).verify_current();  // секреты не загружаются
}

FileId Vault::add_bytes(std::string_view filename, ByteView data) {
    FileId id{};
    impl_->last_profile = {};
    impl_->transaction([&] {
        do {
            impl_->backends.random->fill(MutableByteView(id));
        } while (std::any_of(impl_->verified.objects.begin(), impl_->verified.objects.end(),
                             [&](const auto& o) { return o.file_id == id; }));
        core::ChangeSet cs;
        cs.added.push_back(core::encrypt_object(*impl_->backends.random, impl_->kek.view(),
                                                impl_->trusted_state.storage_uuid, id, filename, data,
                                                &impl_->last_profile));
        impl_->last_profile +=
            core::CommitProtocol(impl_->backends, *impl_->storage, *impl_->trusted).commit(impl_->verified, cs).profile;
    });
    return id;
}

FileId Vault::add_file(const std::filesystem::path& file) {
    PhaseProfile read;
    SecureBytes data;
    {
        ScopedPhase p(&read, Phase::Filesystem);
        data = storage::read_file_secure(file);
    }
    std::string name = file.filename().string();
    FileId id = add_bytes(name, data.view());
    impl_->last_profile += read;
    return id;
}

ExtractedFile Vault::extract(const FileId& id) {
    impl_->last_profile = {};
    auto it = impl_->find(id);
    encoding::FilePlaintext p = core::decrypt_object(impl_->kek.view(), *it, &impl_->last_profile);
    return ExtractedFile{std::move(p.filename), std::move(p.file_data)};
}

void Vault::remove(const FileId& id) {
    impl_->last_profile = {};
    impl_->transaction([&] {
        impl_->find(id);  // NotFound, если файла нет (в т.ч. после обновления состояния)
        core::ChangeSet cs;
        cs.removed.push_back(id);
        impl_->last_profile +=
            core::CommitProtocol(impl_->backends, *impl_->storage, *impl_->trusted).commit(impl_->verified, cs).profile;
    });
}

std::vector<ObjectInfo> Vault::list(bool decrypt_names) {
    std::vector<ObjectInfo> out;
    impl_->last_profile = {};
    for (const auto& o : impl_->verified.objects) {
        ObjectInfo info;
        info.file_id = o.file_id;
        info.ciphertext_size = o.ciphertext.size();
        if (decrypt_names) info.filename = core::decrypt_object(impl_->kek.view(), o, &impl_->last_profile).filename;
        out.push_back(std::move(info));
    }
    return out;
}

core::VerifyReport Vault::verify() {
    core::StateVerifier verifier(impl_->backends, *impl_->storage, *impl_->trusted);
    core::VerifyReport report = verifier.verify_current();
    impl_->verified = report.state;
    impl_->trusted_state = report.trusted_state;
    return report;
}

std::size_t Vault::garbage_collect() {
    std::size_t n = 0;
    impl_->transaction([&] {
        n = core::CommitProtocol(impl_->backends, *impl_->storage, *impl_->trusted).garbage_collect();
    });
    return n;
}

const core::VerifiedState& Vault::state() const { return impl_->verified; }
const PhaseProfile& Vault::open_profile() const { return impl_->open_profile; }
const PhaseProfile& Vault::last_profile() const { return impl_->last_profile; }

}  // namespace vault
