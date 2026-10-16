#pragma once
// Backend ML-KEM-768 (CPU: liboqs; GPU: cuPQC).
// Batch API работает с плоскими непрерывными буферами фиксированного шага
// (count * size) — единый бинарный формат для CPU и GPU (Milestone 4, задача 3).

#include <cstddef>
#include <optional>
#include <string_view>

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"
#include "vault/common/timing.hpp"

namespace vault::crypto {

struct KemKeyPair {
    Bytes public_key;        // kMlKem768PublicKeySize
    SecureBytes secret_key;  // kMlKem768SecretKeySize
};

struct KemEncapsResult {
    Bytes ciphertext;           // kMlKem768CiphertextSize
    SecureBytes shared_secret;  // 32
};

// Плоские буферы batch. Секретные части — SecureBytes.
struct KemBatch {
    std::size_t count = 0;
    Bytes public_keys;           // count * 1184
    SecureBytes secret_keys;     // count * 2400
    Bytes ciphertexts;           // count * 1088
    SecureBytes shared_secrets;  // count * 32
};

class IKemBackend {
public:
    virtual ~IKemBackend() = default;
    virtual std::string_view name() const = 0;

    // seed (d||z, 64 байта) — только для test vectors / CPU==GPU сравнения;
    // std::nullopt -> CSPRNG.
    virtual KemKeyPair keygen(std::optional<ByteView> seed) = 0;
    // m (32 байта) — аналогично.
    virtual KemEncapsResult encaps(ByteView public_key, std::optional<ByteView> m) = 0;
    // ML-KEM implicit rejection: при неверном ct возвращает псевдослучайный
    // секрет, а не ошибку. Поэтому CT_KEM ОБЯЗАН быть проверен через
    // kem_ct_hash из подписанного Manifest до вызова decaps (§21, §27 шаг 8).
    virtual SecureBytes decaps(ByteView secret_key, ByteView ciphertext) = 0;

    // Batch: заполняют соответствующие поля KemBatch.
    // seeds (если заданы): count*64 для keygen, count*32 для encaps.
    virtual void keygen_batch(std::size_t count, std::optional<ByteView> seeds, KemBatch& out,
                              TimingBreakdown* timing) = 0;
    // Вход: batch.public_keys; выход: batch.ciphertexts, batch.shared_secrets.
    virtual void encaps_batch(KemBatch& batch, std::optional<ByteView> seeds,
                              TimingBreakdown* timing) = 0;
    // Вход: batch.secret_keys, batch.ciphertexts; выход: batch.shared_secrets.
    virtual void decaps_batch(KemBatch& batch, TimingBreakdown* timing) = 0;
};

}  // namespace vault::crypto
