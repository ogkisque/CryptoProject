#pragma once
// Обёртки над CUDA runtime для GPU backend'ов: CUDA_CHECK, RAII-буферы, stream'ы, события.
// Код рассчитан на CUDA >= 12.0; здесь он не компилируется (docs/gpu_workflow.md).

#include <cuda_runtime.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

#include "vault/common/error.hpp"
#include "vault/gpu/gpu_options.hpp"

namespace vault::gpu {

// Бросает VaultError(CryptoError) с выражением, местом вызова и текстом ошибки CUDA.
[[noreturn]] void cuda_fail(const char* expr, const char* file, int line, cudaError_t err);

#define CUDA_CHECK(expr)                                                              \
    do {                                                                              \
        const cudaError_t vault_cuda_err_ = (expr);                                   \
        if (vault_cuda_err_ != cudaSuccess)                                           \
            ::vault::gpu::cuda_fail(#expr, __FILE__, __LINE__, vault_cuda_err_);      \
    } while (0)

// Проверка запуска kernel'а: ошибки конфигурации видны сразу, ошибки выполнения — при синхронизации.
#define CUDA_CHECK_LAUNCH(name) CUDA_CHECK_NAMED(cudaGetLastError(), name)
#define CUDA_CHECK_NAMED(expr, name)                                                  \
    do {                                                                              \
        const cudaError_t vault_cuda_err_ = (expr);                                   \
        if (vault_cuda_err_ != cudaSuccess)                                           \
            ::vault::gpu::cuda_fail("launch of kernel " name, __FILE__, __LINE__, vault_cuda_err_); \
    } while (0)

using Clock = std::chrono::steady_clock;
inline double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

// Device-память. reserve() растит буфер (cudaFree + cudaMalloc); время растущего вызова уходит в *alloc_ms.
class DeviceBuffer {
public:
    DeviceBuffer() = default;
    ~DeviceBuffer() { release(nullptr); }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;

    void reserve(std::size_t bytes, double* alloc_ms) {
        if (bytes == 0) bytes = 1;  // cudaMalloc(0) возвращает nullptr — kernel'у нужен валидный указатель
        if (bytes <= cap_) return;
        const auto t0 = Clock::now();
        release(nullptr);
        CUDA_CHECK(cudaMalloc(&ptr_, bytes));
        cap_ = bytes;
        if (alloc_ms) *alloc_ms += ms_since(t0);
    }
    void release(double* alloc_ms) noexcept {
        if (!ptr_) return;
        const auto t0 = Clock::now();
        cudaFree(ptr_);  // в деструкторе исключения недопустимы
        ptr_ = nullptr;
        cap_ = 0;
        if (alloc_ms) *alloc_ms += ms_since(t0);
    }
    template <typename T = std::uint8_t>
    T* get() const noexcept { return static_cast<T*>(ptr_); }
    std::size_t capacity() const noexcept { return cap_; }

private:
    void* ptr_ = nullptr;
    std::size_t cap_ = 0;
};

// Pinned host-память (cudaHostAlloc): быстрый DMA без промежуточной копии драйвера.
class PinnedBuffer {
public:
    PinnedBuffer() = default;
    ~PinnedBuffer() { release(nullptr); }
    PinnedBuffer(const PinnedBuffer&) = delete;
    PinnedBuffer& operator=(const PinnedBuffer&) = delete;

    void reserve(std::size_t bytes, double* alloc_ms) {
        if (bytes == 0) bytes = 1;
        if (bytes <= cap_) return;
        const auto t0 = Clock::now();
        release(nullptr);
        CUDA_CHECK(cudaHostAlloc(&ptr_, bytes, cudaHostAllocDefault));
        cap_ = bytes;
        if (alloc_ms) *alloc_ms += ms_since(t0);
    }
    void release(double* alloc_ms) noexcept {
        if (!ptr_) return;
        const auto t0 = Clock::now();
        cudaFreeHost(ptr_);
        ptr_ = nullptr;
        cap_ = 0;
        if (alloc_ms) *alloc_ms += ms_since(t0);
    }
    template <typename T = std::uint8_t>
    T* get() const noexcept { return static_cast<T*>(ptr_); }
    std::size_t capacity() const noexcept { return cap_; }

private:
    void* ptr_ = nullptr;
    std::size_t cap_ = 0;
};

class Stream {
public:
    Stream() { CUDA_CHECK(cudaStreamCreateWithFlags(&s_, cudaStreamNonBlocking)); }
    ~Stream() { if (s_) cudaStreamDestroy(s_); }
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    cudaStream_t get() const noexcept { return s_; }
    void synchronize() const { CUDA_CHECK(cudaStreamSynchronize(s_)); }

private:
    cudaStream_t s_ = nullptr;
};

class Event {
public:
    Event() { CUDA_CHECK(cudaEventCreate(&e_)); }
    ~Event() { if (e_) cudaEventDestroy(e_); }
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;
    void record(const Stream& s) const { CUDA_CHECK(cudaEventRecord(e_, s.get())); }
    cudaEvent_t get() const noexcept { return e_; }

private:
    cudaEvent_t e_ = nullptr;
};

// Миллисекунды между двумя записанными и завершёнными событиями.
inline double elapsed_ms(const Event& a, const Event& b) {
    float ms = 0;
    CUDA_CHECK(cudaEventElapsedTime(&ms, a.get(), b.get()));
    return static_cast<double>(ms);
}

// Контекст устройства: выбирает device, «прогревает» драйвер (первый CUDA-вызов создаёт контекст,
// ~100+ мс — он должен уйти в конструктор, а не в замеры) и вычисляет размер порции.
class GpuContext {
public:
    explicit GpuContext(const GpuOptions& opt);
    const GpuOptions& options() const noexcept { return opt_; }
    // Максимум device-байт на порцию SHA3-batch'а (на один слот).
    std::size_t max_chunk_bytes() const noexcept { return max_chunk_bytes_; }
    unsigned slots() const noexcept { return opt_.double_buffering ? 2u : 1u; }

private:
    GpuOptions opt_;
    std::size_t max_chunk_bytes_ = 0;
};

constexpr unsigned kBlockSize = 128;

}  // namespace vault::gpu
