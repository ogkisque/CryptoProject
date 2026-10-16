#pragma once
// Набор вычислительных backend'ов, через который vault-логика выполняет
// SHA3/Merkle/ML-KEM/ML-DSA. Формат хранилища от backend'а не зависит.
//
//   Vault logic -> CryptoBackends -> { CPU | CPU-MT | GPU }

#include <memory>
#include <string_view>

#include "vault/crypto/hash_backend.hpp"
#include "vault/crypto/kem_backend.hpp"
#include "vault/crypto/random.hpp"
#include "vault/crypto/sig_backend.hpp"

namespace vault::merkle {
class IMerkleBackend;
}

namespace vault::crypto {

enum class BackendKind {
    Cpu,          // эталонный однопоточный
    CpuParallel,  // многопоточный CPU (для честного сравнения с GPU в batch)
    Gpu,          // CUDA/cuPQC, доступен только при сборке с VAULT_ENABLE_CUDA
};

struct BackendConfig {
    BackendKind kind = BackendKind::Cpu;
    unsigned cpu_threads = 0;  // 0 -> std::thread::hardware_concurrency()
    int cuda_device = 0;
    bool pinned_host_memory = true;
};

struct CryptoBackends {
    std::shared_ptr<IHashBackend> hash;
    std::shared_ptr<merkle::IMerkleBackend> merkle;
    std::shared_ptr<IKemBackend> kem;
    std::shared_ptr<ISigBackend> sig;
    std::shared_ptr<IRandom> random;
};

// Бросает VaultError(BackendUnavailable), если запрошен GPU без CUDA-сборки
// или без устройства.
CryptoBackends make_backends(const BackendConfig& cfg);
bool gpu_backend_compiled() noexcept;
BackendKind parse_backend_kind(std::string_view s);  // "cpu" | "cpu-mt" | "gpu"
std::string_view to_string(BackendKind k) noexcept;

}  // namespace vault::crypto
