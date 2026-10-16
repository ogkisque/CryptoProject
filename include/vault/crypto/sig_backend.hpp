#pragma once
// Backend ML-DSA-65 (CPU: liboqs; GPU: cuPQC). Подпись — "pure" ML-DSA
// (FIPS 204, не HashML-DSA) с context string. Для Manifest контекст
// = label::kManifestSigContext.

#include <cstddef>
#include <optional>
#include <string_view>

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"
#include "vault/common/timing.hpp"

namespace vault::crypto {

struct SigKeyPair {
    Bytes public_key;        // kMlDsa65PublicKeySize
    SecureBytes secret_key;  // kMlDsa65SecretKeySize
};

// Batch с сообщениями фиксированной длины (в проекте подписывается только
// Manifest = 168 байт, этого достаточно и для benchmark).
struct SigBatch {
    std::size_t count = 0;
    std::size_t message_size = 0;
    Bytes public_keys;      // count * 1952
    SecureBytes secret_keys;  // count * 4032
    Bytes messages;         // count * message_size
    Bytes signatures;       // count * 3309
    std::vector<std::uint8_t> verify_ok;  // count, 1 = valid
};

class ISigBackend {
public:
    virtual ~ISigBackend() = default;
    virtual std::string_view name() const = 0;

    virtual SigKeyPair keygen(std::optional<ByteView> seed) = 0;
    // rnd: 32 байта; std::nullopt -> hedged (CSPRNG). 0^32 -> детерминированный вариант
    // (используется для сравнения CPU==GPU байт-в-байт).
    virtual Bytes sign(ByteView secret_key, ByteView message, std::string_view context,
                       std::optional<ByteView> rnd) = 0;
    virtual bool verify(ByteView public_key, ByteView message, std::string_view context,
                        ByteView signature) = 0;

    virtual void keygen_batch(std::size_t count, std::optional<ByteView> seeds, SigBatch& out,
                              TimingBreakdown* timing) = 0;
    // Вход: secret_keys, messages; выход: signatures.
    virtual void sign_batch(SigBatch& batch, std::string_view context,
                            std::optional<ByteView> rnds, TimingBreakdown* timing) = 0;
    // Вход: public_keys, messages, signatures; выход: verify_ok.
    virtual void verify_batch(SigBatch& batch, std::string_view context,
                              TimingBreakdown* timing) = 0;
};

}  // namespace vault::crypto
