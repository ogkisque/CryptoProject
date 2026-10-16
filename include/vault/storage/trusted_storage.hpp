#pragma once
// Доверенная область (§4): ключи + TrustedState. Хранится ОТДЕЛЬНО от vault/.
// В прототипе — локальная директория с правами 0700/0600:
//   trusted/
//     trusted_state.bin   (TrustedStateV1, атомарная замена)
//     keys/kem.pk kem.sk  (M1+)
//     keys/sig.pk sig.sk  (M2+)
// Предполагается, что атакующий не может её читать/менять/откатывать.

#include <filesystem>
#include <memory>
#include <optional>

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"
#include "vault/encoding/trusted_state.hpp"

namespace vault::storage {

struct TrustedPublicKeys {
    Bytes kem_pk;
    std::optional<Bytes> sig_pk;  // отсутствует в хранилищах M1
};

struct TrustedKeys {
    Bytes kem_pk;
    SecureBytes kem_sk;
    std::optional<Bytes> sig_pk;
    std::optional<SecureBytes> sig_sk;
};

class ITrustedStorage {
public:
    virtual ~ITrustedStorage() = default;

    virtual bool exists() const = 0;
    // Создаёт доверенную область; ошибка, если она уже есть.
    virtual void initialize(const TrustedKeys& keys, const encoding::TrustedStateV1& state) = 0;

    virtual encoding::TrustedStateV1 load_state() const = 0;
    virtual TrustedPublicKeys load_public_keys() const = 0;
    // Секретные ключи загружаются по требованию и живут минимально.
    virtual SecureBytes load_kem_secret_key() const = 0;
    virtual SecureBytes load_sig_secret_key() const = 0;

    // Атомарное durable обновление state anchor (§28 шаг 8):
    // tmp + fsync + rename + fsync(dir).
    virtual void update_state(const encoding::TrustedStateV1& state) = 0;
};

std::unique_ptr<ITrustedStorage> make_file_trusted_storage(const std::filesystem::path& dir);

}  // namespace vault::storage
