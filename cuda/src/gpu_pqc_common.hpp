#pragma once
// Общие части GPU ML-KEM / ML-DSA на cuPQC-PK (этап 6): защита вызовов библиотеки, библиотечные буферы с
// гарантированным обнулением (§43), таймер фаз, динамическая shared memory.
//
// API cuPQC-PK (host: make_workspace / get_entropy / destroy_workspace / release_entropy; device:
// Descriptor().execute(...)) — по документации NVIDIA и официальным примерам NVIDIA/cuPQC (examples/public_key):
//   https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_pk/api/host.html
//   https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_pk/api/device.html
//   https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_pk/api/traits.html
// Не компилировалось с настоящим cuPQC (docs/gpu_workflow.md).

#include <pk.hpp>

#include <exception>
#include <vector>
#include <string>

#include "src/gpu_runtime.hpp"

namespace vault::gpu::pqc {

// Вызовы cuPQC при ошибке выделения бросают std::runtime_error (документация host-функций): превращаем их в
// VaultError с указанием, КАКОЙ вызов упал.
template <class F>
auto guard(const char* what, F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const VaultError&) {
        throw;
    } catch (const std::exception& e) {
        throw VaultError(ErrorCode::CryptoError, std::string("cuPQC ") + what + " failed: " + e.what());
    }
}

// Workspace, выделенный cuPQC (make_workspace): перед возвратом в библиотеку обнуляется — внутри могут
// оставаться промежуточные значения секретных операций.
class LibWorkspace {
public:
    LibWorkspace() = default;
    LibWorkspace(const LibWorkspace&) = delete;
    LibWorkspace& operator=(const LibWorkspace&) = delete;
    ~LibWorkspace() { release(); }

    template <class D>
    void acquire(std::size_t batch, cudaStream_t stream, TimingBreakdown& tb) {
        const auto t0 = Clock::now();
        ptr_ = guard("make_workspace", [&] { return cupqc::make_workspace<D>(batch, stream); });
        bytes_ = batch * D::workspace_size;
        stream_ = stream;
        tb.alloc_ms += ms_since(t0);
    }
    std::uint8_t* get() const noexcept { return ptr_; }

    void release() noexcept {
        if (!ptr_) return;
        if (bytes_ > 0) cudaMemsetAsync(ptr_, 0, bytes_, stream_);
        cudaStreamSynchronize(stream_);
        try {
            cupqc::destroy_workspace(ptr_, stream_);
        } catch (...) {
        }
        ptr_ = nullptr;
    }

private:
    std::uint8_t* ptr_ = nullptr;
    std::size_t bytes_ = 0;
    cudaStream_t stream_ = nullptr;
};

// Entropy от cuPQC (get_entropy: криптостойкая случайность, заполняется библиотекой; пользовательского seed в API нет).
// Время генерации — отдельно в TimingBreakdown::entropy_ms.
class LibEntropy {
public:
    LibEntropy() = default;
    LibEntropy(const LibEntropy&) = delete;
    LibEntropy& operator=(const LibEntropy&) = delete;
    ~LibEntropy() { release(); }

    template <class D>
    void acquire(std::size_t batch, cudaStream_t stream, TimingBreakdown& tb) {
        const auto t0 = Clock::now();
        ptr_ = guard("get_entropy", [&] { return cupqc::get_entropy<D>(batch, stream); });
        bytes_ = batch * D::entropy_size;
        stream_ = stream;
        CUDA_CHECK(cudaStreamSynchronize(stream));  // генерация идёт на устройстве: дождаться, чтобы измерить честно
        tb.entropy_ms += ms_since(t0);
    }
    std::uint8_t* get() const noexcept { return ptr_; }

    void release() noexcept {
        if (!ptr_) return;
        if (bytes_ > 0) cudaMemsetAsync(ptr_, 0, bytes_, stream_);
        cudaStreamSynchronize(stream_);
        try {
            cupqc::release_entropy(ptr_, stream_);
        } catch (...) {
        }
        ptr_ = nullptr;
    }

private:
    std::uint8_t* ptr_ = nullptr;
    std::size_t bytes_ = 0;
    cudaStream_t stream_ = nullptr;
};

// События одной операции: H2D, kernel, D2H. Время считается после синхронизации stream'а.
class OpTimer {
public:
    explicit OpTimer(cudaStream_t s) : s_(s) {}
    // h2d_begin() можно звать несколько раз: интервал начинается с первого вызова, заканчивается последним h2d_end().
    void h2d_begin() {
        if (!h2d_started_) h2d0_.record(s_);
        h2d_started_ = true;
    }
    void h2d_end() { h2d1_.record(s_); have_h2d_ = true; }
    void kernel_begin() { k0_.record(s_); }
    void kernel_end() { k1_.record(s_); }
    void d2h_begin() { d0_.record(s_); }
    void d2h_end() { d1_.record(s_); }
    // Вызывать после cudaStreamSynchronize.
    void collect(TimingBreakdown& tb) const {
        if (have_h2d_) tb.h2d_ms += elapsed_ms(h2d0_, h2d1_);
        tb.kernel_ms += elapsed_ms(k0_, k1_);
        tb.d2h_ms += elapsed_ms(d0_, d1_);
    }

private:
    cudaStream_t s_;
    Event h2d0_, h2d1_, k0_, k1_, d0_, d1_;
    bool have_h2d_ = false;
    bool h2d_started_ = false;
};

// cuPQC ML-DSA требует больше 48 КиБ shared memory на блок: нужен динамический shared memory с opt-in.

template <class Kernel>
void ensure_smem(Kernel* kernel, std::size_t bytes, int device, const char* name) {
    if (bytes <= 48 * 1024) return;
    int optin = 0;
    CUDA_CHECK(cudaDeviceGetAttribute(&optin, cudaDevAttrMaxSharedMemoryPerBlockOptin, device));
    if (bytes > static_cast<std::size_t>(optin))
        throw VaultError(ErrorCode::BackendUnavailable,
                         std::string("cuPQC kernel ") + name + " needs " + std::to_string(bytes) +
                             " bytes of shared memory per block, device allows " + std::to_string(optin));
    CUDA_CHECK(cudaFuncSetAttribute(kernel, cudaFuncAttributeMaxDynamicSharedMemorySize, static_cast<int>(bytes)));
}

// Копирование плотного массива из host в строки device с шагом dst_pitch (padding) и обратно.
inline void h2d_rows(void* dst, std::size_t dst_pitch, const void* src, std::size_t width, std::size_t rows, cudaStream_t s) {
    if (width == 0 || rows == 0) return;
    CUDA_CHECK(cudaMemcpy2DAsync(dst, dst_pitch, src, width, width, rows, cudaMemcpyHostToDevice, s));
}
inline void d2h_rows(void* dst, const void* src, std::size_t src_pitch, std::size_t width, std::size_t rows, cudaStream_t s) {
    if (width == 0 || rows == 0) return;
    CUDA_CHECK(cudaMemcpy2DAsync(dst, width, src, src_pitch, width, rows, cudaMemcpyDeviceToHost, s));
}

// Секретный device-буфер: обнуляется перед освобождением/возвратом в пул (§43).
inline void release_secret(DeviceBuffer& b, cudaStream_t s, bool keep_in_pool, double* alloc_ms) {
    b.zero_async(s);
    CUDA_CHECK(cudaStreamSynchronize(s));
    if (!keep_in_pool) b.release(alloc_ms);
}

}  // namespace vault::gpu::pqc

namespace vault::gpu::pqc {

// Освобождает device-буферы операции при выходе из области видимости — и при успехе, и при исключении.
// Секретные буферы предварительно обнуляются (§43). pool = true: буферы остаются в пуле (уже обнулёнными).
class BufGuard {
public:
    BufGuard(cudaStream_t s, bool pool, double* alloc_ms) : s_(s), pool_(pool), alloc_ms_(alloc_ms) {}
    BufGuard(const BufGuard&) = delete;
    BufGuard& operator=(const BufGuard&) = delete;
    void add(DeviceBuffer& b, bool secret) { items_.push_back({&b, secret}); }
    ~BufGuard() {
        cudaStreamSynchronize(s_);  // ни одна операция в полёте не должна читать/писать освобождаемые буферы
        bool need_sync = false;
        for (auto& it : items_)
            if (it.secret) {
                it.buf->zero_async(s_);
                need_sync = true;
            }
        if (need_sync) cudaStreamSynchronize(s_);
        if (!pool_)
            for (auto& it : items_) it.buf->release(alloc_ms_);
    }

private:
    struct Item {
        DeviceBuffer* buf;
        bool secret;
    };
    cudaStream_t s_;
    bool pool_;
    double* alloc_ms_;
    std::vector<Item> items_;
};

}  // namespace vault::gpu::pqc
