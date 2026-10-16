// Заглушки GPU ML-KEM / ML-DSA на время, пока (или если) cuPQC недоступен: фабрики дают BackendUnavailable,
// а SHA3/Merkle на GPU работают независимо (docs/gpu_workflow.md). Реализации появятся на этапе 6
// (cuda/src/gpu_kem_backend.cu, gpu_sig_backend.cu) и компилируются при VAULT_HAS_CUPQC.
#ifndef VAULT_HAS_CUPQC

#include "vault/common/error.hpp"
#include "vault/gpu/gpu_backends.hpp"

namespace vault::gpu {

std::shared_ptr<crypto::IKemBackend> make_gpu_kem_backend(const GpuOptions&) {
    throw VaultError(ErrorCode::BackendUnavailable, "gpu ML-KEM: cuPQC is not available in this build");
}

std::shared_ptr<crypto::ISigBackend> make_gpu_sig_backend(const GpuOptions&) {
    throw VaultError(ErrorCode::BackendUnavailable, "gpu ML-DSA: cuPQC is not available in this build");
}

}  // namespace vault::gpu

#endif  // !VAULT_HAS_CUPQC
