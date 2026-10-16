// ML-KEM-768 на GPU через cuPQC-PK (этап 6). Не компилировалось с настоящим cuPQC (docs/gpu_workflow.md).
//
// Модель cuPQC-PK: device-библиотека, одна операция = один CUDA-блок (Block, BlockDim<128>); каждый блок получает
// свои срезы буферов по traits (public_key_size, secret_key_size, entropy_size, workspace_size) и
// shared memory (shared_memory_size). Здесь — runner одной порции (cuda/host/pqc_runner.hpp); проверка размеров,
// порционирование и сборка IKemBackend — переносимый код cuda/host/pqc_backends.cpp, проверенный на CPU.
//
// Источник случайности: get_entropy<D>(batch) — библиотека сама заполняет криптостойкую entropy; API для
// пользовательского seed в документации нет. Для детерминированных тестов (ACVP) entropy-буфер подменяется
// собственным device-буфером с seed'ом. UNVERIFIED(cuPQC): что байты entropy — это ровно FIPS 203 d||z (keygen,
// 64 байта) и m (encaps, 32 байта). Предположение разрешено только при entropy_size == длине seed
// (supports_seeds()); иначе seeded-операции отказывают с BackendUnavailable. Тест tests/gpu/gpu_pqc_test.cpp
// сверяет результат с ACVP и пропускается (с причиной), если предположение не подтвердилось.
#include <memory>

#include "host/pqc_backends.hpp"
#include "host/pqc_batch_plan.hpp"
#include "src/gpu_pqc_common.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/gpu/gpu_backends.hpp"

namespace vault::gpu {

namespace {

using KemKeygenD = decltype(cupqc::ML_KEM_768() + cupqc::Function<cupqc::function::Keygen>() + cupqc::Block() + cupqc::BlockDim<128>());
using KemEncapsD = decltype(cupqc::ML_KEM_768() + cupqc::Function<cupqc::function::Encaps>() + cupqc::Block() + cupqc::BlockDim<128>());
using KemDecapsD = decltype(cupqc::ML_KEM_768() + cupqc::Function<cupqc::function::Decaps>() + cupqc::Block() + cupqc::BlockDim<128>());

// Размеры cuPQC обязаны совпасть с форматом проекта (FIPS 203), а элементы — лежать с шагом, кратным 8
// (требование выравнивания execute): иначе сборка падает здесь, а не портит данные.
static_assert(KemKeygenD::public_key_size == kMlKem768PublicKeySize, "cuPQC ML-KEM-768 public key size differs from FIPS 203");
static_assert(KemKeygenD::secret_key_size == kMlKem768SecretKeySize, "cuPQC ML-KEM-768 secret key size differs from FIPS 203");
static_assert(KemEncapsD::ciphertext_size == kMlKem768CiphertextSize, "cuPQC ML-KEM-768 ciphertext size differs from FIPS 203");
static_assert(KemEncapsD::shared_secret_size == kMlKem768SharedSecretSize, "cuPQC ML-KEM-768 shared secret size differs from FIPS 203");
static_assert(kMlKem768PublicKeySize % 8 == 0 && kMlKem768SecretKeySize % 8 == 0 && kMlKem768CiphertextSize % 8 == 0 &&
                  kMlKem768SharedSecretSize % 8 == 0,
              "dense per-item layout requires 8-byte multiples");

template <class D>
__global__ void kem_keygen_kernel(std::uint8_t* pks, std::uint8_t* sks, std::uint8_t* entropy, std::uint8_t* workspace) {
    extern __shared__ __align__(16) std::uint8_t smem[];
    const std::size_t b = blockIdx.x;
    D().execute(pks + b * D::public_key_size, sks + b * D::secret_key_size, entropy + b * D::entropy_size,
                workspace + b * D::workspace_size, smem);
}

template <class D>
__global__ void kem_encaps_kernel(std::uint8_t* cts, std::uint8_t* sss, const std::uint8_t* pks, std::uint8_t* entropy,
                                  std::uint8_t* workspace) {
    extern __shared__ __align__(16) std::uint8_t smem[];
    const std::size_t b = blockIdx.x;
    D().execute(cts + b * D::ciphertext_size, sss + b * D::shared_secret_size, pks + b * D::public_key_size,
                entropy + b * D::entropy_size, workspace + b * D::workspace_size, smem);
}

template <class D>
__global__ void kem_decaps_kernel(std::uint8_t* sss, const std::uint8_t* cts, const std::uint8_t* sks, std::uint8_t* workspace) {
    extern __shared__ __align__(16) std::uint8_t smem[];
    const std::size_t b = blockIdx.x;
    D().execute(sss + b * D::shared_secret_size, cts + b * D::ciphertext_size, sks + b * D::secret_key_size,
                workspace + b * D::workspace_size, smem);
}

class CuPqcKemRunner final : public IMlKemRunner {
public:
    explicit CuPqcKemRunner(const GpuOptions& opt) : ctx_(opt), pool_(opt.pool_buffers) {}

    std::uint64_t max_chunk_bytes() const override { return ctx_.max_chunk_bytes(); }
    std::uint64_t keygen_item_bytes() const override {
        return KemKeygenD::public_key_size + KemKeygenD::secret_key_size + KemKeygenD::entropy_size * 2 + KemKeygenD::workspace_size;
    }
    std::uint64_t encaps_item_bytes() const override {
        return KemEncapsD::public_key_size + KemEncapsD::ciphertext_size + KemEncapsD::shared_secret_size +
               KemEncapsD::entropy_size * 2 + KemEncapsD::workspace_size;
    }
    std::uint64_t decaps_item_bytes() const override {
        return KemDecapsD::secret_key_size + KemDecapsD::ciphertext_size + KemDecapsD::shared_secret_size + KemDecapsD::workspace_size;
    }
    bool supports_seeds() const override {
        return KemKeygenD::entropy_size == kMlKem768KeygenSeedSize && KemEncapsD::entropy_size == kMlKem768EncapsSeedSize;
    }

    void keygen(std::size_t n, const std::uint8_t* seeds, std::uint8_t* pk_out, std::uint8_t* sk_out, TimingBreakdown& tb) override {
        using D = KemKeygenD;
        cudaStream_t st = stream_.get();
        pqc::BufGuard guard(st, pool_, &tb.alloc_ms);
        guard.add(d_pk_, false);
        guard.add(d_sk_, true);
        guard.add(d_ent_, true);
        pqc::LibWorkspace ws;
        pqc::LibEntropy lib_ent;
        pqc::OpTimer t(st);

        ws.acquire<D>(n, st, tb);
        d_pk_.reserve(n * D::public_key_size, &tb.alloc_ms);
        d_sk_.reserve(n * D::secret_key_size, &tb.alloc_ms);
        std::uint8_t* entropy = prepare_entropy<D>(n, seeds, kMlKem768KeygenSeedSize, lib_ent, t, tb);

        pqc::ensure_smem(&kem_keygen_kernel<D>, D::shared_memory_size, ctx_.options().device, "kem_keygen_kernel");
        t.kernel_begin();
        kem_keygen_kernel<D><<<static_cast<unsigned>(n), D::BlockDim, D::shared_memory_size, st>>>(d_pk_.get(), d_sk_.get(), entropy, ws.get());
        CUDA_CHECK_LAUNCH("kem_keygen_kernel");
        t.kernel_end();

        t.d2h_begin();
        pqc::d2h_rows(pk_out, d_pk_.get(), D::public_key_size, D::public_key_size, n, st);
        pqc::d2h_rows(sk_out, d_sk_.get(), D::secret_key_size, D::secret_key_size, n, st);
        t.d2h_end();
        wait(st, t, tb);
    }

    void encaps(std::size_t n, const std::uint8_t* pks, const std::uint8_t* seeds, std::uint8_t* ct_out, std::uint8_t* ss_out,
                TimingBreakdown& tb) override {
        using D = KemEncapsD;
        cudaStream_t st = stream_.get();
        pqc::BufGuard guard(st, pool_, &tb.alloc_ms);
        guard.add(d_pk_, false);
        guard.add(d_ct_, false);
        guard.add(d_ss_, true);
        guard.add(d_ent_, true);
        pqc::LibWorkspace ws;
        pqc::LibEntropy lib_ent;
        pqc::OpTimer t(st);

        ws.acquire<D>(n, st, tb);
        d_pk_.reserve(n * D::public_key_size, &tb.alloc_ms);
        d_ct_.reserve(n * D::ciphertext_size, &tb.alloc_ms);
        d_ss_.reserve(n * D::shared_secret_size, &tb.alloc_ms);
        t.h2d_begin();
        pqc::h2d_rows(d_pk_.get(), D::public_key_size, pks, D::public_key_size, n, st);
        t.h2d_end();
        std::uint8_t* entropy = prepare_entropy<D>(n, seeds, kMlKem768EncapsSeedSize, lib_ent, t, tb);

        pqc::ensure_smem(&kem_encaps_kernel<D>, D::shared_memory_size, ctx_.options().device, "kem_encaps_kernel");
        t.kernel_begin();
        kem_encaps_kernel<D><<<static_cast<unsigned>(n), D::BlockDim, D::shared_memory_size, st>>>(d_ct_.get(), d_ss_.get(), d_pk_.get(), entropy, ws.get());
        CUDA_CHECK_LAUNCH("kem_encaps_kernel");
        t.kernel_end();

        t.d2h_begin();
        pqc::d2h_rows(ct_out, d_ct_.get(), D::ciphertext_size, D::ciphertext_size, n, st);
        pqc::d2h_rows(ss_out, d_ss_.get(), D::shared_secret_size, D::shared_secret_size, n, st);
        t.d2h_end();
        wait(st, t, tb);
    }

    void decaps(std::size_t n, const std::uint8_t* sks, const std::uint8_t* cts, std::uint8_t* ss_out, TimingBreakdown& tb) override {
        using D = KemDecapsD;
        cudaStream_t st = stream_.get();
        pqc::BufGuard guard(st, pool_, &tb.alloc_ms);
        guard.add(d_sk_, true);
        guard.add(d_ct_, false);
        guard.add(d_ss_, true);
        pqc::LibWorkspace ws;
        pqc::OpTimer t(st);

        ws.acquire<D>(n, st, tb);
        d_sk_.reserve(n * D::secret_key_size, &tb.alloc_ms);
        d_ct_.reserve(n * D::ciphertext_size, &tb.alloc_ms);
        d_ss_.reserve(n * D::shared_secret_size, &tb.alloc_ms);
        t.h2d_begin();
        pqc::h2d_rows(d_sk_.get(), D::secret_key_size, sks, D::secret_key_size, n, st);
        pqc::h2d_rows(d_ct_.get(), D::ciphertext_size, cts, D::ciphertext_size, n, st);
        t.h2d_end();

        pqc::ensure_smem(&kem_decaps_kernel<D>, D::shared_memory_size, ctx_.options().device, "kem_decaps_kernel");
        t.kernel_begin();
        kem_decaps_kernel<D><<<static_cast<unsigned>(n), D::BlockDim, D::shared_memory_size, st>>>(d_ss_.get(), d_ct_.get(), d_sk_.get(), ws.get());
        CUDA_CHECK_LAUNCH("kem_decaps_kernel");
        t.kernel_end();

        t.d2h_begin();
        pqc::d2h_rows(ss_out, d_ss_.get(), D::shared_secret_size, D::shared_secret_size, n, st);
        t.d2h_end();
        wait(st, t, tb);
    }

private:
    // Entropy из библиотеки (seeds == nullptr) или собственный буфер с seed'ом (детерминированный режим).
    template <class D>
    std::uint8_t* prepare_entropy(std::size_t n, const std::uint8_t* seeds, std::size_t seed_len, pqc::LibEntropy& lib,
                                  pqc::OpTimer& t, TimingBreakdown& tb) {
        cudaStream_t st = stream_.get();
        if (!seeds) {
            lib.acquire<D>(n, st, tb);
            return lib.get();
        }
        d_ent_.reserve(n * D::entropy_size, &tb.alloc_ms);
        CUDA_CHECK(cudaMemsetAsync(d_ent_.get(), 0, n * D::entropy_size, st));
        t.h2d_begin();
        pqc::h2d_rows(d_ent_.get(), D::entropy_size, seeds, seed_len, n, st);
        t.h2d_end();
        return d_ent_.get();
    }

    void wait(cudaStream_t st, pqc::OpTimer& t, TimingBreakdown& tb) {
        const auto t0 = Clock::now();
        CUDA_CHECK(cudaStreamSynchronize(st));
        tb.sync_ms += ms_since(t0);
        t.collect(tb);
    }

    GpuContext ctx_;
    bool pool_;
    Stream stream_;
    DeviceBuffer d_pk_, d_sk_, d_ct_, d_ss_, d_ent_;
};

}  // namespace

std::shared_ptr<crypto::IKemBackend> make_gpu_kem_backend(const GpuOptions& opt) {
    return make_pqc_kem_backend(std::make_unique<CuPqcKemRunner>(opt));
}

}  // namespace vault::gpu
