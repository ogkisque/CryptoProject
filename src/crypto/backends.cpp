#include "vault/crypto/backends.hpp"

#include "vault/common/error.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/common/thread_pool.hpp"
#include "vault/merkle/merkle.hpp"
#ifdef VAULT_HAS_CUDA
#include "vault/gpu/gpu_backends.hpp"
#endif

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
    CryptoBackends b;
    switch (cfg.kind) {
        case BackendKind::Cpu: {
            b.hash = make_cpu_hash_backend(1);
            b.merkle = merkle::make_reference_merkle(b.hash);
            b.kem = make_cpu_kem_backend(1);
            b.sig = make_cpu_sig_backend(1);
            break;
        }
        case BackendKind::CpuParallel: {
            unsigned t = resolve_thread_count(cfg.cpu_threads);
            b.hash = make_cpu_hash_backend(t);
            b.merkle = merkle::make_parallel_merkle(b.hash, t);
            b.kem = make_cpu_kem_backend(t);
            b.sig = make_cpu_sig_backend(t);
            break;
        }
        case BackendKind::Gpu: {
#ifdef VAULT_HAS_CUDA
            // GPU — только ускоритель (§41, §43): симметричная криптография и RNG остаются на CPU.
            if (!gpu::cuda_device_available())
                throw VaultError(ErrorCode::BackendUnavailable, "gpu backend: no CUDA device available");
            gpu::GpuOptions opt;
            opt.device = cfg.cuda_device;
            opt.pinned_host_memory = cfg.pinned_host_memory;
            opt.double_buffering = cfg.gpu_double_buffering;
            opt.pool_buffers = cfg.gpu_pool_buffers;
            opt.hash_strategy = cfg.gpu_hash_strategy;
            opt.max_chunk_bytes = cfg.gpu_max_chunk_bytes;
            opt.merkle_cpu_threshold = cfg.gpu_merkle_cpu_threshold;
            b.hash = gpu::make_gpu_hash_backend(opt);
            b.merkle = gpu::make_gpu_merkle_backend(opt);
            // ML-KEM/ML-DSA на GPU (этап 6) могут быть недоступны (нет cuPQC). Тогда vault работает с
            // CPU-реализацией, а benchmark по name() != "gpu" помечает такие точки как skipped, а не
            // выдаёт CPU-замер за GPU. Так сбой PQC не мешает SHA3/Merkle.
            try {
                b.kem = gpu::make_gpu_kem_backend(opt);
            } catch (const VaultError& e) {
                if (e.code() != ErrorCode::BackendUnavailable) throw;
                b.kem = make_cpu_kem_backend(1);
            }
            try {
                b.sig = gpu::make_gpu_sig_backend(opt);
            } catch (const VaultError& e) {
                if (e.code() != ErrorCode::BackendUnavailable) throw;
                b.sig = make_cpu_sig_backend(1);
            }
            break;
#else
            throw VaultError(ErrorCode::BackendUnavailable, "gpu backend: not compiled in (build with VAULT_ENABLE_CUDA=ON)");
#endif
        }
    }
    b.random = make_system_random();
    return b;
}

}  // namespace vault::crypto
