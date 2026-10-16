// ML-DSA-65 на GPU через cuPQC-PK (этап 6). Не компилировалось с настоящим cuPQC (docs/gpu_workflow.md).
//
// Особенности cuPQC-PK ML-DSA (по документации и examples/public_key/example_ml_dsa.cu):
//  * подпись занимает signature_size байт, НЕ кратных 8, а execute требует 8-байтового выравнивания: на device
//    подписи лежат с шагом round_up_8(signature_size) = 3312, на host — плотно по 3309 (cudaMemcpy2DAsync);
//  * Sign/Verify не принимают context string — только message и message_length. Что именно подписывается, и
//    значит как получить подпись, совместимую с FIPS 204 «pure» с ctx, определяет калибровка в
//    cuda/host/pqc_backends.cpp (UNVERIFIED(cuPQC): внутренний режим M' или pure с пустым ctx);
//  * ML-DSA-65 sign/verify может требовать > 48 КиБ shared memory на блок -> динамическая shared memory с opt-in
//    (cudaFuncSetAttribute), а не статический __shared__ массив;
//  * entropy: get_entropy<D>(batch) — как у ML-KEM; seeded-режим только при entropy_size == длине seed
//    (xi для keygen, rnd для sign — 32 байта); UNVERIFIED(cuPQC): что байты entropy — именно FIPS 204 xi / rnd.
#include <algorithm>
#include <memory>

#include "host/pqc_backends.hpp"
#include "host/pqc_batch_plan.hpp"
#include "src/gpu_pqc_common.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/gpu/gpu_backends.hpp"

namespace vault::gpu {

namespace {

using DsaKeygenD = decltype(cupqc::ML_DSA_65() + cupqc::Function<cupqc::function::Keygen>() + cupqc::Block() + cupqc::BlockDim<128>());
using DsaSignD = decltype(cupqc::ML_DSA_65() + cupqc::Function<cupqc::function::Sign>() + cupqc::Block() + cupqc::BlockDim<128>());
using DsaVerifyD = decltype(cupqc::ML_DSA_65() + cupqc::Function<cupqc::function::Verify>() + cupqc::Block() + cupqc::BlockDim<128>());

static_assert(DsaKeygenD::public_key_size == kMlDsa65PublicKeySize, "cuPQC ML-DSA-65 public key size differs from FIPS 204");
static_assert(DsaKeygenD::secret_key_size == kMlDsa65SecretKeySize, "cuPQC ML-DSA-65 secret key size differs from FIPS 204");
static_assert(DsaSignD::signature_size == kMlDsa65SignatureSize, "cuPQC ML-DSA-65 signature size differs from FIPS 204");
static_assert(kMlDsa65PublicKeySize % 8 == 0 && kMlDsa65SecretKeySize % 8 == 0, "dense per-item layout requires 8-byte multiples");

constexpr std::size_t kSigStride = round_up_8(kMlDsa65SignatureSize);  // 3312

template <class D>
__global__ void dsa_keygen_kernel(std::uint8_t* pks, std::uint8_t* sks, std::uint8_t* entropy, std::uint8_t* workspace) {
    extern __shared__ __align__(16) std::uint8_t smem[];
    const std::size_t b = blockIdx.x;
    D().execute(pks + b * D::public_key_size, sks + b * D::secret_key_size, entropy + b * D::entropy_size,
                workspace + b * D::workspace_size, smem);
}

template <class D>
__global__ void dsa_sign_kernel(std::uint8_t* sigs, const std::uint8_t* msgs, std::size_t msg_size, std::size_t msg_stride,
                                const std::uint8_t* sks, std::uint8_t* entropy, std::uint8_t* workspace) {
    extern __shared__ __align__(16) std::uint8_t smem[];
    const std::size_t b = blockIdx.x;
    D().execute(sigs + b * kSigStride, msgs + b * msg_stride, msg_size, sks + b * D::secret_key_size,
                entropy + b * D::entropy_size, workspace + b * D::workspace_size, smem);
}

template <class D>
__global__ void dsa_verify_kernel(bool* valids, const std::uint8_t* sigs, const std::uint8_t* msgs, std::size_t msg_size,
                                  std::size_t msg_stride, const std::uint8_t* pks, std::uint8_t* workspace) {
    extern __shared__ __align__(16) std::uint8_t smem[];
    const std::size_t b = blockIdx.x;
    // Как в официальном примере: результат пишут все потоки блока (значение одинаково).
    valids[b] = D().execute(msgs + b * msg_stride, msg_size, sigs + b * kSigStride, pks + b * D::public_key_size,
                            workspace + b * D::workspace_size, smem);
}

class CuPqcDsaRunner final : public IMlDsaRunner {
public:
    explicit CuPqcDsaRunner(const GpuOptions& opt) : ctx_(opt), pool_(opt.pool_buffers) {}

    std::uint64_t max_chunk_bytes() const override { return ctx_.max_chunk_bytes(); }
    std::uint64_t keygen_item_bytes() const override {
        return DsaKeygenD::public_key_size + DsaKeygenD::secret_key_size + DsaKeygenD::entropy_size * 2 + DsaKeygenD::workspace_size;
    }
    std::uint64_t sign_item_bytes(std::size_t m) const override {
        return kSigStride + round_up_8(m) + DsaSignD::secret_key_size + DsaSignD::entropy_size * 2 + DsaSignD::workspace_size;
    }
    std::uint64_t verify_item_bytes(std::size_t m) const override {
        return kSigStride + round_up_8(m) + DsaVerifyD::public_key_size + 1 + DsaVerifyD::workspace_size;
    }
    bool supports_seeds() const override {
        return DsaKeygenD::entropy_size == kMlDsa65KeygenSeedSize && DsaSignD::entropy_size == kMlDsa65SignRandSize;
    }

    void keygen(std::size_t n, const std::uint8_t* seeds, std::uint8_t* pk_out, std::uint8_t* sk_out, TimingBreakdown& tb) override {
        using D = DsaKeygenD;
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
        std::uint8_t* entropy = prepare_entropy<D>(n, seeds, kMlDsa65KeygenSeedSize, lib_ent, t, tb);

        pqc::ensure_smem(&dsa_keygen_kernel<D>, D::shared_memory_size, ctx_.options().device, "dsa_keygen_kernel");
        t.kernel_begin();
        dsa_keygen_kernel<D><<<static_cast<unsigned>(n), D::BlockDim, D::shared_memory_size, st>>>(d_pk_.get(), d_sk_.get(), entropy, ws.get());
        CUDA_CHECK_LAUNCH("dsa_keygen_kernel");
        t.kernel_end();

        t.d2h_begin();
        pqc::d2h_rows(pk_out, d_pk_.get(), D::public_key_size, D::public_key_size, n, st);
        pqc::d2h_rows(sk_out, d_sk_.get(), D::secret_key_size, D::secret_key_size, n, st);
        t.d2h_end();
        wait(st, t, tb);
    }

    void sign(std::size_t n, const std::uint8_t* sks, const std::uint8_t* msgs, std::size_t msize, const std::uint8_t* rnds,
              std::uint8_t* sig_out, TimingBreakdown& tb) override {
        using D = DsaSignD;
        cudaStream_t st = stream_.get();
        const std::size_t mstride = round_up_8(msize);
        pqc::BufGuard guard(st, pool_, &tb.alloc_ms);
        guard.add(d_sk_, true);
        guard.add(d_msg_, false);
        guard.add(d_sig_, false);
        guard.add(d_ent_, true);
        pqc::LibWorkspace ws;
        pqc::LibEntropy lib_ent;
        pqc::OpTimer t(st);

        ws.acquire<D>(n, st, tb);
        d_sk_.reserve(n * D::secret_key_size, &tb.alloc_ms);
        d_msg_.reserve(n * std::max<std::size_t>(mstride, 8), &tb.alloc_ms);
        d_sig_.reserve(n * kSigStride, &tb.alloc_ms);
        // Entropy — до H2D: LibEntropy::acquire синхронизирует stream, и иначе entropy_ms включал бы копирование.
        std::uint8_t* entropy = prepare_entropy<D>(n, rnds, kMlDsa65SignRandSize, lib_ent, t, tb);
        t.h2d_begin();
        pqc::h2d_rows(d_sk_.get(), D::secret_key_size, sks, D::secret_key_size, n, st);
        pqc::h2d_rows(d_msg_.get(), mstride, msgs, msize, n, st);  // строки с padding до 8
        t.h2d_end();

        pqc::ensure_smem(&dsa_sign_kernel<D>, D::shared_memory_size, ctx_.options().device, "dsa_sign_kernel");
        t.kernel_begin();
        dsa_sign_kernel<D><<<static_cast<unsigned>(n), D::BlockDim, D::shared_memory_size, st>>>(
            d_sig_.get(), d_msg_.get(), msize, mstride, d_sk_.get(), entropy, ws.get());
        CUDA_CHECK_LAUNCH("dsa_sign_kernel");
        t.kernel_end();

        t.d2h_begin();
        pqc::d2h_rows(sig_out, d_sig_.get(), kSigStride, kMlDsa65SignatureSize, n, st);  // плотные 3309 на host
        t.d2h_end();
        wait(st, t, tb);
    }

    void verify(std::size_t n, const std::uint8_t* pks, const std::uint8_t* msgs, std::size_t msize, const std::uint8_t* sigs,
                std::uint8_t* ok, TimingBreakdown& tb) override {
        using D = DsaVerifyD;
        cudaStream_t st = stream_.get();
        const std::size_t mstride = round_up_8(msize);
        pqc::BufGuard guard(st, pool_, &tb.alloc_ms);
        guard.add(d_pk_, false);
        guard.add(d_msg_, false);
        guard.add(d_sig_, false);
        guard.add(d_ok_, false);
        pqc::LibWorkspace ws;
        pqc::OpTimer t(st);

        ws.acquire<D>(n, st, tb);
        d_pk_.reserve(n * D::public_key_size, &tb.alloc_ms);
        d_msg_.reserve(n * std::max<std::size_t>(mstride, 8), &tb.alloc_ms);
        d_sig_.reserve(n * kSigStride, &tb.alloc_ms);
        d_ok_.reserve(n * sizeof(bool), &tb.alloc_ms);
        t.h2d_begin();
        pqc::h2d_rows(d_pk_.get(), D::public_key_size, pks, D::public_key_size, n, st);
        pqc::h2d_rows(d_msg_.get(), mstride, msgs, msize, n, st);
        pqc::h2d_rows(d_sig_.get(), kSigStride, sigs, kMlDsa65SignatureSize, n, st);
        t.h2d_end();

        pqc::ensure_smem(&dsa_verify_kernel<D>, D::shared_memory_size, ctx_.options().device, "dsa_verify_kernel");
        t.kernel_begin();
        dsa_verify_kernel<D><<<static_cast<unsigned>(n), D::BlockDim, D::shared_memory_size, st>>>(
            d_ok_.get<bool>(), d_sig_.get(), d_msg_.get(), msize, mstride, d_pk_.get(), ws.get());
        CUDA_CHECK_LAUNCH("dsa_verify_kernel");
        t.kernel_end();

        t.d2h_begin();
        static_assert(sizeof(bool) == 1, "verify results are copied as bytes");
        CUDA_CHECK(cudaMemcpyAsync(ok, d_ok_.get(), n, cudaMemcpyDeviceToHost, st));
        t.d2h_end();
        wait(st, t, tb);
        for (std::size_t i = 0; i < n; ++i) ok[i] = ok[i] ? 1 : 0;  // нормализовать bool -> 0/1
    }

private:
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
    DeviceBuffer d_pk_, d_sk_, d_msg_, d_sig_, d_ent_, d_ok_;
};

}  // namespace

std::shared_ptr<crypto::ISigBackend> make_gpu_sig_backend(const GpuOptions& opt) {
    return make_pqc_sig_backend(std::make_unique<CuPqcDsaRunner>(opt), crypto::make_cpu_sig_backend(1));
}

}  // namespace vault::gpu
