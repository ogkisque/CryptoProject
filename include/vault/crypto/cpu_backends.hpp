#pragma once
// Эталонные CPU backend'ы: SHA3 — OpenSSL EVP, ML-KEM/ML-DSA — liboqs.
// threads > 1 включает распараллеливание batch-операций (CpuParallel).

#include <memory>

#include "vault/crypto/hash_backend.hpp"
#include "vault/crypto/kem_backend.hpp"
#include "vault/crypto/sig_backend.hpp"

namespace vault::crypto {

std::shared_ptr<IHashBackend> make_cpu_hash_backend(unsigned threads);
std::shared_ptr<IKemBackend> make_cpu_kem_backend(unsigned threads);
std::shared_ptr<ISigBackend> make_cpu_sig_backend(unsigned threads);

}  // namespace vault::crypto
