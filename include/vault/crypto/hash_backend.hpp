#pragma once
// Backend SHA3-256 (CPU: OpenSSL; GPU: CUDA Keccak / cuPQC cuHash).
// Требование §42: результат GPU == CPU байт-в-байт.

#include <cstdint>
#include <span>
#include <string_view>

#include "vault/common/bytes.hpp"
#include "vault/common/timing.hpp"

namespace vault::crypto {

class IHashBackend {
public:
    virtual ~IHashBackend() = default;

    virtual std::string_view name() const = 0;

    // Сырой SHA3-256 (для test vectors).
    virtual Hash256 sha3_256(ByteView data) = 0;

    // Domain-separated: SHA3-256(domain || data). Префикс подаётся в sponge
    // без копирования data (важно для больших ciphertext).
    virtual Hash256 domain_hash(std::uint8_t domain, ByteView data) = 0;

    // Пакетные варианты для независимых входов. out.size() == inputs.size().
    // timing может быть nullptr.
    virtual void sha3_256_batch(std::span<const ByteView> inputs, std::span<Hash256> out,
                                TimingBreakdown* timing) = 0;
    virtual void domain_hash_batch(std::uint8_t domain, std::span<const ByteView> inputs,
                                   std::span<Hash256> out, TimingBreakdown* timing) = 0;
};

}  // namespace vault::crypto
