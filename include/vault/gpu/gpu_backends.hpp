#pragma once
// GPU backend'ы (Milestone 5-6). Компилируются только при VAULT_ENABLE_CUDA=ON
// (cuda/src/*.cu). Целевая карта — RTX 3050, SM 86.
// GPU — только ускоритель, не доверенная зона (§41, §43): временные буферы
// с секретами обнуляются (cudaMemsetAsync) после операции.

#include <memory>
#include <string>

#include "vault/crypto/hash_backend.hpp"
#include "vault/gpu/gpu_options.hpp"
#include "vault/crypto/kem_backend.hpp"
#include "vault/crypto/sig_backend.hpp"
#include "vault/merkle/merkle.hpp"

namespace vault::gpu {

struct GpuDeviceInfo {
    int device = 0;
    std::string name;
    int sm_major = 0, sm_minor = 0;
    std::size_t total_memory = 0;
    int multiprocessors = 0;
    int runtime_version = 0, driver_version = 0;
};


bool cuda_device_available() noexcept;
GpuDeviceInfo query_device(int device);

std::shared_ptr<crypto::IHashBackend> make_gpu_hash_backend(const GpuOptions& opt);
std::shared_ptr<merkle::IMerkleBackend> make_gpu_merkle_backend(const GpuOptions& opt);
// Merkle поверх уже созданного GPU hash-backend'а (листья считает он). Так в одном наборе backend'ов один
// экземпляр GPU-хеширования: два независимых экземпляра каждый рассчитывали бы на 60% свободной VRAM, и при
// pool_buffers = true их буферы не поместились бы вместе на карте с 4 GiB.
std::shared_ptr<merkle::IMerkleBackend> make_gpu_merkle_backend(const GpuOptions& opt,
                                                                std::shared_ptr<crypto::IHashBackend> hash);
std::shared_ptr<crypto::IKemBackend> make_gpu_kem_backend(const GpuOptions& opt);
std::shared_ptr<crypto::ISigBackend> make_gpu_sig_backend(const GpuOptions& opt);

}  // namespace vault::gpu
