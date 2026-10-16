#include "vault/crypto/backends.hpp"

#include "vault/common/error.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/merkle/merkle.hpp"

namespace vault::crypto {

bool gpu_backend_compiled() noexcept {
#ifdef VAULT_HAS_CUDA
    return true;
#else
    return false;
#endif
}

BackendKind parse_backend_kind(std::string_view s) {
    if (s == "cpu") return BackendKind::Cpu;
    if (s == "cpu-mt") return BackendKind::CpuParallel;
    if (s == "gpu") return BackendKind::Gpu;
    throw VaultError(ErrorCode::InvalidArgument, "unknown backend (expected cpu|cpu-mt|gpu)");
}

std::string_view to_string(BackendKind k) noexcept {
    switch (k) {
        case BackendKind::Cpu: return "cpu";
        case BackendKind::CpuParallel: return "cpu-mt";
        case BackendKind::Gpu: return "gpu";
    }
    return "?";
}

CryptoBackends make_backends(const BackendConfig& cfg) {
    switch (cfg.kind) {
        case BackendKind::Cpu: break;
        case BackendKind::CpuParallel:
            throw VaultError(ErrorCode::BackendUnavailable, "cpu-mt backend: not implemented yet (stage 4)");
        case BackendKind::Gpu:
            throw VaultError(ErrorCode::BackendUnavailable, "gpu backend: not available (stages 5-6)");
    }
    CryptoBackends b;
    b.hash = make_cpu_hash_backend(1);
    b.kem = make_cpu_kem_backend(1);
    b.random = make_system_random();
    b.merkle = merkle::make_reference_merkle(b.hash);
    b.sig = make_cpu_sig_backend(1);
    return b;
}

}  // namespace vault::crypto
