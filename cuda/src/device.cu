// Устройство, контекст и общие ошибки GPU-части (этап 5). Не компилировалось локально (нет CUDA).
#include <algorithm>
#include <sstream>

#include "src/gpu_runtime.hpp"
#include "vault/gpu/gpu_backends.hpp"

namespace vault::gpu {

void cuda_fail(const char* expr, const char* file, int line, cudaError_t err) {
    // Сбросить «залипшую» ошибку, чтобы она не всплыла в следующем, не связанном вызове.
    (void)cudaGetLastError();
    std::ostringstream os;
    os << "CUDA error at " << file << ":" << line << ": `" << expr << "` -> " << cudaGetErrorName(err) << " ("
       << cudaGetErrorString(err) << ")";
    throw VaultError(ErrorCode::CryptoError, os.str());
}

bool cuda_device_available() noexcept {
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess) {
        (void)cudaGetLastError();
        return false;
    }
    return n > 0;
}

GpuDeviceInfo query_device(int device) {
    cudaDeviceProp p{};
    CUDA_CHECK(cudaGetDeviceProperties(&p, device));
    GpuDeviceInfo info;
    info.device = device;
    info.name = p.name;
    info.sm_major = p.major;
    info.sm_minor = p.minor;
    info.total_memory = p.totalGlobalMem;
    info.multiprocessors = p.multiProcessorCount;
    CUDA_CHECK(cudaRuntimeGetVersion(&info.runtime_version));
    CUDA_CHECK(cudaDriverGetVersion(&info.driver_version));
    return info;
}

GpuContext::GpuContext(const GpuOptions& opt) : opt_(opt) {
    int n = 0;
    CUDA_CHECK(cudaGetDeviceCount(&n));
    if (opt.device < 0 || opt.device >= n)
        throw VaultError(ErrorCode::BackendUnavailable,
                         "gpu backend: CUDA device " + std::to_string(opt.device) + " not found (devices: " + std::to_string(n) + ")");
    CUDA_CHECK(cudaSetDevice(opt.device));
    CUDA_CHECK(cudaFree(nullptr));  // создаёт контекст сейчас, а не в первом замере

    constexpr std::size_t kDefaultCap = std::size_t{1} << 30;  // 1 GiB
    if (opt.max_chunk_bytes != 0) {
        max_chunk_bytes_ = opt.max_chunk_bytes;
    } else {
        std::size_t free_b = 0, total_b = 0;
        CUDA_CHECK(cudaMemGetInfo(&free_b, &total_b));
        // На все слоты вместе — не больше 60% свободной памяти.
        max_chunk_bytes_ = std::min<std::size_t>(kDefaultCap, static_cast<std::size_t>(free_b * 0.6) / slots());
    }
    if (max_chunk_bytes_ < (std::size_t{1} << 20)) max_chunk_bytes_ = std::size_t{1} << 20;
}

}  // namespace vault::gpu
