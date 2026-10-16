#pragma once
// Фасад хранилища — то, что вызывает CLI. Все операции, кроме init,
// работают только с проверенным состоянием (§34). Результат проверки
// кэшируется в пределах процесса до первого изменения.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"
#include "vault/common/timing.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/vault/state_verifier.hpp"

namespace vault {

struct VaultPaths {
    std::filesystem::path vault_dir;    // недоверенное хранилище
    std::filesystem::path trusted_dir;  // доверенная область
};

struct ObjectInfo {
    FileId file_id{};
    std::uint64_t ciphertext_size = 0;
    std::optional<std::string> filename;  // только если list(decrypt_names=true)
};

struct ExtractedFile {
    std::string filename;
    SecureBytes data;
};

class Vault {
public:
    // vault init (§51). Ошибка, если vault_dir или trusted_dir уже существуют.
    static void init(const VaultPaths& paths, const crypto::CryptoBackends& backends);

    // Только проверка состояния (`vault verify`): секретные ключи не загружаются, Decaps не вызывается.
    static core::VerifyReport verify_state(const VaultPaths& paths, const crypto::CryptoBackends& backends);

    // Открывает и полностью проверяет текущее состояние (бросает VerificationError).
    static Vault open(const VaultPaths& paths, crypto::CryptoBackends backends);

    Vault(Vault&&) noexcept;
    Vault& operator=(Vault&&) noexcept;
    ~Vault();  // обнуляет KEK и прочие секреты

    FileId add_file(const std::filesystem::path& file);
    FileId add_bytes(std::string_view filename, ByteView data);
    ExtractedFile extract(const FileId& id);
    void remove(const FileId& id);
    std::vector<ObjectInfo> list(bool decrypt_names);
    // Повторная полная проверка с диска (vault verify).
    core::VerifyReport verify();
    std::size_t garbage_collect();

    const core::VerifiedState& state() const;

    // Профиль фаз (§4.4): проверка состояния при open() и последняя операция (add/extract/remove/list).
    const PhaseProfile& open_profile() const;
    const PhaseProfile& last_profile() const;

private:
    struct Impl;
    explicit Vault(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

}  // namespace vault
