// SHA3-256 на GPU (этап 5). Не компилировалось локально (нет CUDA).
//
// Логика конвейера порций (порционирование, ротация слотов, порядок завершения, сборка staging) — в
// cuda/host/hash_pipeline.hpp и проверена на CPU эмулированным устройством; логика kernel'ов — общий код
// kernels/keccak.cuh, проверенный против OpenSSL. Здесь — только CUDA-часть: буферы, копирования, запуск.
//
// Фазы в TimingBreakdown:
//   alloc_ms  — cudaMalloc/cudaHostAlloc/free (при pool_buffers = false — на каждый вызов)
//   h2d_ms    — сборка staging-буфера на CPU + DMA host->device (по cudaEvent)
//   kernel_ms — выполнение kernel'а (по cudaEvent)
//   d2h_ms    — DMA device->host + копирование из pinned-буфера в выход (если pinned)
//   sync_ms   — время ожидания cudaStreamSynchronize на CPU
// При double_buffering сумма фаз может превышать total_ms (фазы перекрываются).
// Хешируются публичные данные (ciphertext), поэтому обнуление буферов не требуется (в отличие от этапа 6).
#include <cstring>
#include <memory>
#include <vector>

#include "host/hash_pipeline.hpp"
#include "host/launch_plan.hpp"
#include "kernels/keccak.cuh"
#include "kernels/keccak_warp.cuh"
#include "src/gpu_runtime.hpp"
#include "vault/crypto/hash_backend.hpp"
#include "vault/gpu/gpu_backends.hpp"

namespace vault::gpu {

namespace {

// Блочное поглощение (sha3_256_domain_blockwise): индексы состояния — константы, s[25] в регистрах.
// UNVERIFIED(perf): число регистров и spill'ы — смотреть в build.log (-Xptxas -v, VAULT_CUDA_PTXAS_VERBOSE).
__global__ void sha3_thread_per_object_kernel(const std::uint8_t* data, const std::uint64_t* offsets,
                                              std::uint64_t count, int domain, std::uint8_t* out) {
    const std::uint64_t stride = static_cast<std::uint64_t>(gridDim.x) * blockDim.x;
    for (std::uint64_t i = static_cast<std::uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x; i < count; i += stride)
        kernels::sha3_256_domain_blockwise(domain, data + offsets[i],
                                           static_cast<std::size_t>(offsets[i + 1] - offsets[i]), out + 32 * i);
}

__global__ void sha3_warp_per_object_kernel(const std::uint8_t* data, const std::uint64_t* offsets,
                                            std::uint64_t count, int domain, std::uint8_t* out) {
    const std::uint64_t global_thread = static_cast<std::uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const unsigned lane = threadIdx.x & 31u;
    const std::uint64_t stride_warps = static_cast<std::uint64_t>(gridDim.x) * blockDim.x / 32;
    // Номер объекта зависит только от warp'а, поэтому все 32 lane'а проходят одинаковое число итераций
    // (иначе __shfl_sync с полной маской зависнет).
    for (std::uint64_t w = global_thread / 32; w < count; w += stride_warps)
        kernels::sha3_256_domain_warp(domain, data + offsets[w], static_cast<std::size_t>(offsets[w + 1] - offsets[w]),
                                      out + 32 * w, lane);
}

// Слот конвейера: stream, события и буферы одной порции.
struct Slot {
    Stream stream;
    Event h2d0, h2d1, k0, k1, d2h0, d2h1;
    DeviceBuffer d_data, d_offsets, d_out;
    PinnedBuffer p_data, p_offsets, p_out;
    std::vector<std::uint8_t> h_data;  // pageable staging (pinned_host_memory = false)
    std::vector<std::uint64_t> h_offsets;
    bool in_flight = false;
    bool staged_pinned = false;
    double stage_ms = 0;

    void release_buffers(double* alloc_ms) noexcept {
        d_data.release(alloc_ms);
        d_offsets.release(alloc_ms);
        d_out.release(alloc_ms);
        p_data.release(alloc_ms);
        p_offsets.release(alloc_ms);
        p_out.release(alloc_ms);
    }
};

// CUDA-реализация контракта Dev из host/hash_pipeline.hpp.
class CudaHashDevice {
public:
    explicit CudaHashDevice(const GpuOptions& opt) : ctx_(opt) {
        for (unsigned i = 0; i < ctx_.slots(); ++i) slots_.push_back(std::make_unique<Slot>());
    }

    unsigned slot_count() const { return static_cast<unsigned>(slots_.size()); }
    std::uint64_t max_chunk_bytes() const { return ctx_.max_chunk_bytes(); }
    bool pooled() const { return ctx_.options().pool_buffers; }

    Staging prepare(unsigned si, const HashChunk& chunk, TimingBreakdown& tb) {
        Slot& s = *slots_[si];
        const std::size_t data_bytes = static_cast<std::size_t>(chunk.byte_end - chunk.byte_begin);
        const std::size_t off_bytes = (chunk.count + 1) * sizeof(std::uint64_t);
        const std::size_t out_bytes = chunk.count * 32;
        s.staged_pinned = ctx_.options().pinned_host_memory;

        s.d_data.reserve(data_bytes, &tb.alloc_ms);
        s.d_offsets.reserve(off_bytes, &tb.alloc_ms);
        s.d_out.reserve(out_bytes, &tb.alloc_ms);
        Staging st;
        if (s.staged_pinned) {
            s.p_data.reserve(data_bytes, &tb.alloc_ms);
            s.p_offsets.reserve(off_bytes, &tb.alloc_ms);
            s.p_out.reserve(out_bytes, &tb.alloc_ms);
            st.data = s.p_data.get();
            st.offsets = s.p_offsets.get<std::uint64_t>();
        } else {
            s.h_data.resize(std::max<std::size_t>(data_bytes, 1));
            s.h_offsets.resize(chunk.count + 1);
            st.data = s.h_data.data();
            st.offsets = s.h_offsets.data();
        }
        return st;
    }

    void launch(unsigned si, const HashChunk& chunk, int domain, Hash256* out_dst, double stage_ms, TimingBreakdown&) {
        Slot& s = *slots_[si];
        const GpuOptions& opt = ctx_.options();
        const std::size_t data_bytes = static_cast<std::size_t>(chunk.byte_end - chunk.byte_begin);
        const std::size_t off_bytes = (chunk.count + 1) * sizeof(std::uint64_t);
        const std::size_t out_bytes = chunk.count * 32;
        const std::uint8_t* h_data = s.staged_pinned ? s.p_data.get() : s.h_data.data();
        const std::uint64_t* h_off = s.staged_pinned ? s.p_offsets.get<std::uint64_t>() : s.h_offsets.data();
        s.stage_ms = stage_ms;

        s.h2d0.record(s.stream);
        if (data_bytes > 0)
            CUDA_CHECK(cudaMemcpyAsync(s.d_data.get(), h_data, data_bytes, cudaMemcpyHostToDevice, s.stream.get()));
        CUDA_CHECK(cudaMemcpyAsync(s.d_offsets.get(), h_off, off_bytes, cudaMemcpyHostToDevice, s.stream.get()));
        s.h2d1.record(s.stream);

        s.k0.record(s.stream);
        if (opt.hash_strategy == GpuHashStrategy::WarpPerObject) {
            const LaunchDims d = launch_dims_warp_per_object(chunk.count, kBlockSize);
            sha3_warp_per_object_kernel<<<d.grid, d.block, 0, s.stream.get()>>>(
                s.d_data.get(), s.d_offsets.get<std::uint64_t>(), chunk.count, domain, s.d_out.get());
        } else {
            const LaunchDims d = launch_dims(chunk.count, kBlockSize);
            sha3_thread_per_object_kernel<<<d.grid, d.block, 0, s.stream.get()>>>(
                s.d_data.get(), s.d_offsets.get<std::uint64_t>(), chunk.count, domain, s.d_out.get());
        }
        CUDA_CHECK_LAUNCH("sha3_*_per_object_kernel");
        s.k1.record(s.stream);

        s.d2h0.record(s.stream);
        void* dst = s.staged_pinned ? static_cast<void*>(s.p_out.get()) : static_cast<void*>(out_dst);
        CUDA_CHECK(cudaMemcpyAsync(dst, s.d_out.get(), out_bytes, cudaMemcpyDeviceToHost, s.stream.get()));
        s.d2h1.record(s.stream);
        s.in_flight = true;
    }

    void finish(unsigned si, const HashChunk& chunk, Hash256* out_dst, TimingBreakdown& tb) {
        Slot& s = *slots_[si];
        const auto t_sync = Clock::now();
        s.stream.synchronize();
        tb.sync_ms += ms_since(t_sync);
        s.in_flight = false;
        tb.h2d_ms += s.stage_ms + elapsed_ms(s.h2d0, s.h2d1);
        tb.kernel_ms += elapsed_ms(s.k0, s.k1);
        tb.d2h_ms += elapsed_ms(s.d2h0, s.d2h1);
        if (s.staged_pinned) {
            const auto t_copy = Clock::now();
            std::memcpy(out_dst, s.p_out.get(), chunk.count * 32);
            tb.d2h_ms += ms_since(t_copy);
        }
    }

    // Дождаться всех порций в полёте (при ошибке: чтобы stream'ы не писали в уже освобождённую память).
    void drain() noexcept {
        for (auto& s : slots_)
            if (s->in_flight) {
                cudaStreamSynchronize(s->stream.get());
                s->in_flight = false;
            }
    }

    void release_if_not_pooled(TimingBreakdown& tb) noexcept {
        if (pooled()) return;
        for (auto& s : slots_) s->release_buffers(&tb.alloc_ms);
    }

private:
    GpuContext ctx_;
    std::vector<std::unique_ptr<Slot>> slots_;
};

class GpuHashBackend final : public crypto::IHashBackend {
public:
    explicit GpuHashBackend(const GpuOptions& opt) : dev_(opt) {}
    ~GpuHashBackend() override { dev_.drain(); }

    std::string_view name() const override { return "gpu"; }

    // Одиночные хеши (kem_ct_hash, key id и т.п.) — протокольные мелочи по 1-2 КБ: запуск kernel'а стоил бы
    // больше самого хеширования, поэтому они считаются на CPU тем же кодом, что и kernel.
    Hash256 sha3_256(ByteView data) override { return host_hash(-1, data); }
    Hash256 domain_hash(std::uint8_t domain, ByteView data) override { return host_hash(domain, data); }

    void sha3_256_batch(std::span<const ByteView> inputs, std::span<Hash256> out, TimingBreakdown* timing) override {
        run(-1, inputs, out, timing);
    }
    void domain_hash_batch(std::uint8_t domain, std::span<const ByteView> inputs, std::span<Hash256> out,
                           TimingBreakdown* timing) override {
        run(domain, inputs, out, timing);
    }

private:
    static Hash256 host_hash(int domain, ByteView data) {
        Hash256 h;
        kernels::sha3_256_domain(domain, data.data(), data.size(), h.data());
        return h;
    }

    void run(int domain, std::span<const ByteView> inputs, std::span<Hash256> out, TimingBreakdown* timing) {
        if (out.size() != inputs.size()) throw VaultError(ErrorCode::InvalidArgument, "batch size mismatch");
        const auto t_total = Clock::now();
        TimingBreakdown tb;
        try {
            run_hash_pipeline(dev_, domain, inputs, out, dev_.max_chunk_bytes(), tb);
        } catch (...) {
            dev_.release_if_not_pooled(tb);
            throw;
        }
        dev_.release_if_not_pooled(tb);
        tb.total_ms = ms_since(t_total);
        if (timing) *timing += tb;
    }

    CudaHashDevice dev_;
};

}  // namespace

std::shared_ptr<crypto::IHashBackend> make_gpu_hash_backend(const GpuOptions& opt) {
    return std::make_shared<GpuHashBackend>(opt);
}

}  // namespace vault::gpu
