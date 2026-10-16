// Логика GPU ML-KEM / ML-DSA (этап 6.A) на «фальшивом cuPQC»: runner'ы поверх liboqs. Проверяются проверка размеров,
// порционирование, калибровка режима context string (все три гипотезы о cuPQC), сборка M', fallback одиночных
// операций, отказы вместо молчаливых подмен. Реальный cuPQC проверяется на GPU-машине (tests/gpu/gpu_pqc_test.cpp).
#include <gtest/gtest.h>

#include <random>

#include "host/pqc_backends.hpp"
#include "vault/common/error.hpp"
#include "vault/crypto/cpu_backends.hpp"

using namespace vault;
using namespace vault::gpu;

namespace {

Bytes rand_bytes(std::mt19937_64& g, std::size_t n) {
    Bytes b(n);
    for (auto& x : b) x = static_cast<std::uint8_t>(g());
    return b;
}

struct KemStats {
    std::vector<std::size_t> keygen_chunks, encaps_chunks, decaps_chunks;
};

class FakeKemRunner final : public IMlKemRunner {
public:
    FakeKemRunner(KemStats* st, std::uint64_t max_chunk, bool seeds) : st_(st), max_(max_chunk), seeds_(seeds) {}
    std::uint64_t max_chunk_bytes() const override { return max_; }
    std::uint64_t keygen_item_bytes() const override { return 3000; }
    std::uint64_t encaps_item_bytes() const override { return 3000; }
    std::uint64_t decaps_item_bytes() const override { return 3000; }
    bool supports_seeds() const override { return seeds_; }

    void keygen(std::size_t n, const std::uint8_t* seeds, std::uint8_t* pk, std::uint8_t* sk, TimingBreakdown& tb) override {
        st_->keygen_chunks.push_back(n);
        tb.kernel_ms += 1;
        for (std::size_t i = 0; i < n; ++i) {
            std::optional<ByteView> s;
            if (seeds) s = ByteView(seeds + i * kMlKem768KeygenSeedSize, kMlKem768KeygenSeedSize);
            auto kp = cpu_->keygen(s);
            std::copy(kp.public_key.begin(), kp.public_key.end(), pk + i * kMlKem768PublicKeySize);
            std::copy(kp.secret_key.data(), kp.secret_key.data() + kp.secret_key.size(), sk + i * kMlKem768SecretKeySize);
        }
    }
    void encaps(std::size_t n, const std::uint8_t* pks, const std::uint8_t* seeds, std::uint8_t* ct, std::uint8_t* ss,
                TimingBreakdown& tb) override {
        st_->encaps_chunks.push_back(n);
        tb.kernel_ms += 1;
        for (std::size_t i = 0; i < n; ++i) {
            std::optional<ByteView> m;
            if (seeds) m = ByteView(seeds + i * kMlKem768EncapsSeedSize, kMlKem768EncapsSeedSize);
            auto r = cpu_->encaps(ByteView(pks + i * kMlKem768PublicKeySize, kMlKem768PublicKeySize), m);
            std::copy(r.ciphertext.begin(), r.ciphertext.end(), ct + i * kMlKem768CiphertextSize);
            std::copy(r.shared_secret.data(), r.shared_secret.data() + 32, ss + i * 32);
        }
    }
    void decaps(std::size_t n, const std::uint8_t* sks, const std::uint8_t* cts, std::uint8_t* ss, TimingBreakdown& tb) override {
        st_->decaps_chunks.push_back(n);
        tb.kernel_ms += 1;
        for (std::size_t i = 0; i < n; ++i) {
            auto r = cpu_->decaps(ByteView(sks + i * kMlKem768SecretKeySize, kMlKem768SecretKeySize),
                                  ByteView(cts + i * kMlKem768CiphertextSize, kMlKem768CiphertextSize));
            std::copy(r.data(), r.data() + 32, ss + i * 32);
        }
    }

private:
    KemStats* st_;
    std::uint64_t max_;
    bool seeds_;
    std::shared_ptr<crypto::IKemBackend> cpu_ = crypto::make_cpu_kem_backend(1);
};

// Гипотезы о том, что делает cuPQC ML-DSA sign/verify над переданным сообщением.
enum class Hypothesis {
    Internal,  // H1: сообщение = M' (Sign_internal)
    Pure,      // H2: «pure» с пустым ctx
    Garbage,   // H3: несовместимо с liboqs
};

struct DsaStats {
    std::vector<std::size_t> sign_chunks, verify_chunks;
    std::vector<std::size_t> sign_msg_sizes;
    int sign_calls = 0;
};

class FakeDsaRunner final : public IMlDsaRunner {
public:
    FakeDsaRunner(DsaStats* st, Hypothesis h, std::uint64_t max_chunk, bool seeds)
        : st_(st), h_(h), max_(max_chunk), seeds_(seeds) {}
    std::uint64_t max_chunk_bytes() const override { return max_; }
    std::uint64_t keygen_item_bytes() const override { return 8000; }
    std::uint64_t sign_item_bytes(std::size_t m) const override { return 8000 + m; }
    std::uint64_t verify_item_bytes(std::size_t m) const override { return 8000 + m; }
    bool supports_seeds() const override { return seeds_; }

    void keygen(std::size_t n, const std::uint8_t* seeds, std::uint8_t* pk, std::uint8_t* sk, TimingBreakdown&) override {
        for (std::size_t i = 0; i < n; ++i) {
            std::optional<ByteView> s;
            if (seeds) s = ByteView(seeds + i * kMlDsa65KeygenSeedSize, kMlDsa65KeygenSeedSize);
            auto kp = cpu_->keygen(s);
            std::copy(kp.public_key.begin(), kp.public_key.end(), pk + i * kMlDsa65PublicKeySize);
            std::copy(kp.secret_key.data(), kp.secret_key.data() + kp.secret_key.size(), sk + i * kMlDsa65SecretKeySize);
        }
    }

    void sign(std::size_t n, const std::uint8_t* sks, const std::uint8_t* msgs, std::size_t msize, const std::uint8_t* rnds,
              std::uint8_t* sigs, TimingBreakdown& tb) override {
        ++st_->sign_calls;
        st_->sign_chunks.push_back(n);
        st_->sign_msg_sizes.push_back(msize);
        tb.kernel_ms += 1;
        for (std::size_t i = 0; i < n; ++i) {
            ByteView sk(sks + i * kMlDsa65SecretKeySize, kMlDsa65SecretKeySize), m(msgs + i * msize, msize);
            std::optional<ByteView> rnd;
            if (rnds) rnd = ByteView(rnds + i * kMlDsa65SignRandSize, kMlDsa65SignRandSize);
            Bytes sig;
            if (h_ == Hypothesis::Internal) {
                if (m.size() < 2 || m[0] != 0 || m[1] > m.size() - 2) throw VaultError(ErrorCode::CryptoError, "fake: malformed M'");
                std::string ctx(reinterpret_cast<const char*>(m.data() + 2), m[1]);
                sig = cpu_->sign(sk, m.subspan(2 + m[1]), ctx, rnd);  // == Sign_internal(M')
            } else if (h_ == Hypothesis::Pure) {
                sig = cpu_->sign(sk, m, "", rnd);
            } else {
                std::mt19937_64 g(i + 1);
                sig = rand_bytes(g, kMlDsa65SignatureSize);
            }
            std::copy(sig.begin(), sig.end(), sigs + i * kMlDsa65SignatureSize);
        }
    }

    void verify(std::size_t n, const std::uint8_t* pks, const std::uint8_t* msgs, std::size_t msize, const std::uint8_t* sigs,
                std::uint8_t* ok, TimingBreakdown& tb) override {
        st_->verify_chunks.push_back(n);
        tb.kernel_ms += 1;
        for (std::size_t i = 0; i < n; ++i) {
            ByteView pk(pks + i * kMlDsa65PublicKeySize, kMlDsa65PublicKeySize), m(msgs + i * msize, msize),
                sig(sigs + i * kMlDsa65SignatureSize, kMlDsa65SignatureSize);
            bool v = false;
            if (h_ == Hypothesis::Internal) {
                if (m.size() >= 2 && m[0] == 0 && m[1] <= m.size() - 2) {
                    std::string ctx(reinterpret_cast<const char*>(m.data() + 2), m[1]);
                    v = cpu_->verify(pk, m.subspan(2 + m[1]), ctx, sig);
                }
            } else if (h_ == Hypothesis::Pure) {
                v = cpu_->verify(pk, m, "", sig);
            }
            ok[i] = v ? 1 : 0;
        }
    }

private:
    DsaStats* st_;
    Hypothesis h_;
    std::uint64_t max_;
    bool seeds_;
    std::shared_ptr<crypto::ISigBackend> cpu_ = crypto::make_cpu_sig_backend(1);
};

constexpr const char* kCtx = "edu-vault-manifest-v1";

std::shared_ptr<crypto::ISigBackend> make_sig(DsaStats* st, Hypothesis h, std::uint64_t max_chunk = 1 << 30, bool seeds = true) {
    return make_pqc_sig_backend(std::make_unique<FakeDsaRunner>(st, h, max_chunk, seeds), crypto::make_cpu_sig_backend(1));
}

crypto::SigBatch make_signed_batch(crypto::ISigBackend& cpu, std::mt19937_64& rng, std::size_t n, std::size_t msize,
                                   std::string_view ctx) {
    crypto::SigBatch b;
    cpu.keygen_batch(n, std::nullopt, b, nullptr);
    b.message_size = msize;
    b.messages = rand_bytes(rng, n * msize);
    cpu.sign_batch(b, ctx, std::nullopt, nullptr);
    return b;
}

}  // namespace

// ------------------------------------------------------------------ ML-KEM

TEST(PqcKem, SeededBatchMatchesCpuAndIsChunked) {
    std::mt19937_64 rng(1);
    KemStats st;
    // порция = 2 элемента (6000 / 3000)
    auto gpu = make_pqc_kem_backend(std::make_unique<FakeKemRunner>(&st, 6000, true));
    auto cpu = crypto::make_cpu_kem_backend(1);
    const std::size_t n = 7;
    Bytes kseeds = rand_bytes(rng, n * kMlKem768KeygenSeedSize), mseeds = rand_bytes(rng, n * kMlKem768EncapsSeedSize);

    crypto::KemBatch a, b;
    cpu->keygen_batch(n, ByteView(kseeds), a, nullptr);
    TimingBreakdown tb;
    gpu->keygen_batch(n, ByteView(kseeds), b, &tb);
    EXPECT_EQ(a.public_keys, b.public_keys);
    EXPECT_EQ(Bytes(a.secret_keys.view().begin(), a.secret_keys.view().end()), Bytes(b.secret_keys.view().begin(), b.secret_keys.view().end()));
    EXPECT_EQ(st.keygen_chunks, (std::vector<std::size_t>{2, 2, 2, 1}));
    EXPECT_EQ(tb.kernel_ms, 4.0);  // тайминги runner'а суммируются по порциям
    EXPECT_GT(tb.total_ms, 0.0);

    cpu->encaps_batch(a, ByteView(mseeds), nullptr);
    gpu->encaps_batch(b, ByteView(mseeds), nullptr);
    EXPECT_EQ(a.ciphertexts, b.ciphertexts);
    EXPECT_EQ(Bytes(a.shared_secrets.view().begin(), a.shared_secrets.view().end()), Bytes(b.shared_secrets.view().begin(), b.shared_secrets.view().end()));
    EXPECT_EQ(st.encaps_chunks, (std::vector<std::size_t>{2, 2, 2, 1}));

    Bytes enc_ss(b.shared_secrets.view().begin(), b.shared_secrets.view().end());
    gpu->decaps_batch(b, nullptr);
    EXPECT_EQ(Bytes(b.shared_secrets.view().begin(), b.shared_secrets.view().end()), enc_ss);
    EXPECT_EQ(st.decaps_chunks.size(), 4u);
}

TEST(PqcKem, SingleOperationsInteroperateWithCpu) {
    KemStats st;
    auto gpu = make_pqc_kem_backend(std::make_unique<FakeKemRunner>(&st, 1 << 30, true));
    auto cpu = crypto::make_cpu_kem_backend(1);
    auto kp = gpu->keygen(std::nullopt);
    ASSERT_EQ(kp.public_key.size(), kMlKem768PublicKeySize);
    ASSERT_EQ(kp.secret_key.size(), kMlKem768SecretKeySize);
    auto e = cpu->encaps(kp.public_key, std::nullopt);               // CPU encaps -> GPU decaps
    SecureBytes via_gpu = gpu->decaps(kp.secret_key.view(), e.ciphertext);
    EXPECT_EQ(Bytes(via_gpu.view().begin(), via_gpu.view().end()), Bytes(e.shared_secret.view().begin(), e.shared_secret.view().end()));
    auto g = gpu->encaps(kp.public_key, std::nullopt);                // GPU encaps -> CPU decaps
    auto d = cpu->decaps(kp.secret_key.view(), g.ciphertext);
    EXPECT_EQ(Bytes(d.view().begin(), d.view().end()), Bytes(g.shared_secret.view().begin(), g.shared_secret.view().end()));
}

TEST(PqcKem, RejectsBadSizesAndUnsupportedSeeds) {
    KemStats st;
    auto gpu = make_pqc_kem_backend(std::make_unique<FakeKemRunner>(&st, 1 << 30, false));
    crypto::KemBatch b;
    Bytes short_seeds(10);
    EXPECT_THROW(gpu->keygen_batch(2, ByteView(short_seeds), b, nullptr), VaultError);  // неверный размер
    Bytes seeds(2 * kMlKem768KeygenSeedSize);
    try {
        gpu->keygen_batch(2, ByteView(seeds), b, nullptr);
        FAIL();
    } catch (const VaultError& e) {
        EXPECT_EQ(e.code(), ErrorCode::BackendUnavailable);  // отказ, а не молчаливая подмена
    }
    EXPECT_NO_THROW(gpu->keygen_batch(2, std::nullopt, b, nullptr));
    crypto::KemBatch bad;
    bad.count = 2;
    bad.public_keys.assign(5, 0);
    EXPECT_THROW(gpu->encaps_batch(bad, std::nullopt, nullptr), VaultError);
    bad.secret_keys = SecureBytes(7);
    EXPECT_THROW(gpu->decaps_batch(bad, nullptr), VaultError);
    EXPECT_EQ(gpu->name(), "gpu");
    EXPECT_EQ(st.keygen_chunks.size(), 1u);  // отвергнутые вызовы runner'а не касались
}

// ------------------------------------------------------------------ ML-DSA

TEST(PqcSig, CalibrationRecognizesAllHypotheses) {
    DsaStats s1, s2, s3;
    auto internal = make_sig(&s1, Hypothesis::Internal), pure = make_sig(&s2, Hypothesis::Pure), garbage = make_sig(&s3, Hypothesis::Garbage);
    EXPECT_EQ(sig_context_mode(*internal), SigContextMode::Internal);
    EXPECT_EQ(sig_context_mode(*pure), SigContextMode::PureEmptyContext);
    EXPECT_EQ(sig_context_mode(*garbage), SigContextMode::Unusable);
    EXPECT_EQ(s1.sign_calls, 1);
    sig_context_mode(*internal);
    EXPECT_EQ(s1.sign_calls, 1);  // калибровка один раз
    auto cpu = crypto::make_cpu_sig_backend(1);
    EXPECT_THROW(sig_context_mode(*cpu), VaultError);
}

TEST(PqcSig, InternalModeIsFullyCompatibleWithLiboqsIncludingContext) {
    std::mt19937_64 rng(2);
    auto cpu = crypto::make_cpu_sig_backend(1);
    for (std::size_t msize : {1u, 8u, 168u, 1000u}) {
        DsaStats st;
        // порция = 3 элемента
        auto gpu = make_sig(&st, Hypothesis::Internal, 3 * (8000 + msize + 2 + 21));
        const std::size_t n = 8;

        // GPU sign -> CPU verify
        crypto::SigBatch b;
        gpu->keygen_batch(n, std::nullopt, b, nullptr);
        b.message_size = msize;
        b.messages = rand_bytes(rng, n * msize);
        gpu->sign_batch(b, kCtx, std::nullopt, nullptr);
        ASSERT_EQ(b.signatures.size(), n * kMlDsa65SignatureSize);
        for (std::size_t i = 0; i < n; ++i)
            EXPECT_TRUE(cpu->verify(ByteView(b.public_keys).subspan(i * kMlDsa65PublicKeySize, kMlDsa65PublicKeySize),
                                    ByteView(b.messages).subspan(i * msize, msize), kCtx,
                                    ByteView(b.signatures).subspan(i * kMlDsa65SignatureSize, kMlDsa65SignatureSize)))
                << "msize=" << msize << " i=" << i;
        // другой контекст не проходит
        EXPECT_FALSE(cpu->verify(ByteView(b.public_keys).subspan(0, kMlDsa65PublicKeySize), ByteView(b.messages).subspan(0, msize), "other",
                                 ByteView(b.signatures).subspan(0, kMlDsa65SignatureSize)));

        // CPU sign -> GPU verify (и порча)
        crypto::SigBatch c = make_signed_batch(*cpu, rng, n, msize, kCtx);
        gpu->verify_batch(c, kCtx, nullptr);
        EXPECT_EQ(std::count(c.verify_ok.begin(), c.verify_ok.end(), 1), static_cast<long>(n));
        c.signatures[2 * kMlDsa65SignatureSize + 40] ^= 1;
        c.messages[5 * msize] ^= 1;
        gpu->verify_batch(c, kCtx, nullptr);
        EXPECT_EQ(c.verify_ok[2], 0);
        EXPECT_EQ(c.verify_ok[5], 0);
        EXPECT_EQ(std::count(c.verify_ok.begin(), c.verify_ok.end(), 1), static_cast<long>(n - 2));
        gpu->verify_batch(c, "wrong-context", nullptr);
        EXPECT_EQ(std::count(c.verify_ok.begin(), c.verify_ok.end(), 1), 0);

        // порции: калибровка (1) + sign по 3 + verify по 3
        EXPECT_EQ(st.sign_chunks.front(), 1u);
        EXPECT_EQ(st.sign_chunks[1], 3u);
        EXPECT_EQ(st.sign_msg_sizes[1], msize + 2 + 21);  // M' = 0x00 || len || ctx || M
    }
}

TEST(PqcSig, InternalModeDeterministicSignMatchesCpuByteForByte) {
    std::mt19937_64 rng(3);
    DsaStats st;
    auto gpu = make_sig(&st, Hypothesis::Internal);
    auto cpu = crypto::make_cpu_sig_backend(1);
    Bytes seed = rand_bytes(rng, kMlDsa65KeygenSeedSize), zero(kMlDsa65SignRandSize, 0), msg = rand_bytes(rng, 168);
    auto kg = gpu->keygen(ByteView(seed)), kc = cpu->keygen(ByteView(seed));
    EXPECT_EQ(kg.public_key, kc.public_key);
    EXPECT_EQ(Bytes(kg.secret_key.view().begin(), kg.secret_key.view().end()), Bytes(kc.secret_key.view().begin(), kc.secret_key.view().end()));
    EXPECT_EQ(gpu->sign(kc.secret_key.view(), msg, kCtx, ByteView(zero)), cpu->sign(kc.secret_key.view(), msg, kCtx, ByteView(zero)));
    EXPECT_TRUE(gpu->verify(kc.public_key, msg, kCtx, cpu->sign(kc.secret_key.view(), msg, kCtx, std::nullopt)));
    EXPECT_TRUE(cpu->verify(kc.public_key, msg, kCtx, gpu->sign(kc.secret_key.view(), msg, kCtx, std::nullopt)));
    Bytes short_sig(10);
    EXPECT_FALSE(gpu->verify(kc.public_key, msg, kCtx, short_sig));  // неверная длина — false, не исключение
}

TEST(PqcSig, PureEmptyContextModeRefusesBatchesWithContextAndFallsBackForSingles) {
    std::mt19937_64 rng(4);
    DsaStats st;
    auto gpu = make_sig(&st, Hypothesis::Pure);
    auto cpu = crypto::make_cpu_sig_backend(1);
    ASSERT_EQ(sig_context_mode(*gpu), SigContextMode::PureEmptyContext);
    const std::size_t n = 5;

    // пустой ctx — на GPU
    crypto::SigBatch b;
    gpu->keygen_batch(n, std::nullopt, b, nullptr);
    b.message_size = 168;
    b.messages = rand_bytes(rng, n * 168);
    gpu->sign_batch(b, "", std::nullopt, nullptr);
    for (std::size_t i = 0; i < n; ++i)
        EXPECT_TRUE(cpu->verify(ByteView(b.public_keys).subspan(i * kMlDsa65PublicKeySize, kMlDsa65PublicKeySize),
                                ByteView(b.messages).subspan(i * 168, 168), "",
                                ByteView(b.signatures).subspan(i * kMlDsa65SignatureSize, kMlDsa65SignatureSize)));
    gpu->verify_batch(b, "", nullptr);
    EXPECT_EQ(std::count(b.verify_ok.begin(), b.verify_ok.end(), 1), static_cast<long>(n));

    // непустой ctx в batch — отказ с BackendUnavailable (benchmark пометит skipped)
    for (int op = 0; op < 2; ++op) {
        try {
            if (op == 0) gpu->sign_batch(b, kCtx, std::nullopt, nullptr);
            else gpu->verify_batch(b, kCtx, nullptr);
            FAIL();
        } catch (const VaultError& e) {
            EXPECT_EQ(e.code(), ErrorCode::BackendUnavailable);
            EXPECT_NE(std::string(e.what()).find("empty context"), std::string::npos) << e.what();
        }
    }
    // одиночные операции с manifest-контекстом идут на CPU и дают корректные FIPS 204 подписи
    auto kp = cpu->keygen(std::nullopt);
    Bytes msg = rand_bytes(rng, 168);
    Bytes sig = gpu->sign(kp.secret_key.view(), msg, kCtx, std::nullopt);
    EXPECT_TRUE(cpu->verify(kp.public_key, msg, kCtx, sig));
    EXPECT_TRUE(gpu->verify(kp.public_key, msg, kCtx, sig));
    sig[7] ^= 1;
    EXPECT_FALSE(gpu->verify(kp.public_key, msg, kCtx, sig));
}

TEST(PqcSig, UnusableModeRefusesBatchesAndFallsBackForSingles) {
    DsaStats st;
    auto gpu = make_sig(&st, Hypothesis::Garbage);
    auto cpu = crypto::make_cpu_sig_backend(1);
    crypto::SigBatch b;
    cpu->keygen_batch(2, std::nullopt, b, nullptr);
    b.message_size = 16;
    b.messages.assign(32, 1);
    for (const char* ctx : {"", kCtx}) {
        try {
            gpu->sign_batch(b, ctx, std::nullopt, nullptr);
            FAIL();
        } catch (const VaultError& e) {
            EXPECT_EQ(e.code(), ErrorCode::BackendUnavailable);
            EXPECT_NE(std::string(e.what()).find("not compatible"), std::string::npos) << e.what();
        }
    }
    auto kp = cpu->keygen(std::nullopt);
    Bytes msg(40, 9);
    EXPECT_TRUE(cpu->verify(kp.public_key, msg, kCtx, gpu->sign(kp.secret_key.view(), msg, kCtx, std::nullopt)));
}

TEST(PqcSig, SeedSupportAndInputValidation) {
    std::mt19937_64 rng(5);
    DsaStats st;
    auto cpu = crypto::make_cpu_sig_backend(1);
    {
        auto gpu = make_sig(&st, Hypothesis::Internal);
        Bytes seeds = rand_bytes(rng, 3 * kMlDsa65KeygenSeedSize);
        crypto::SigBatch a, b;
        cpu->keygen_batch(3, ByteView(seeds), a, nullptr);
        gpu->keygen_batch(3, ByteView(seeds), b, nullptr);
        EXPECT_EQ(a.public_keys, b.public_keys);
        EXPECT_EQ(Bytes(a.secret_keys.view().begin(), a.secret_keys.view().end()), Bytes(b.secret_keys.view().begin(), b.secret_keys.view().end()));
        EXPECT_THROW(gpu->keygen_batch(3, ByteView(seeds).subspan(0, 10), b, nullptr), VaultError);
        EXPECT_THROW(gpu->sign_batch(b, std::string(256, 'x'), std::nullopt, nullptr), VaultError);  // ctx > 255
        b.message_size = 4;
        b.messages.assign(5, 0);  // не count * message_size
        EXPECT_THROW(gpu->sign_batch(b, kCtx, std::nullopt, nullptr), VaultError);
        EXPECT_THROW(gpu->verify_batch(b, kCtx, nullptr), VaultError);
    }
    {
        auto gpu = make_sig(&st, Hypothesis::Internal, 1 << 30, /*seeds=*/false);
        crypto::SigBatch b;
        cpu->keygen_batch(1, std::nullopt, b, nullptr);
        b.message_size = 8;
        b.messages.assign(8, 1);
        Bytes rnd(kMlDsa65SignRandSize, 0);
        try {
            gpu->sign_batch(b, kCtx, ByteView(rnd), nullptr);
            FAIL();
        } catch (const VaultError& e) {
            EXPECT_EQ(e.code(), ErrorCode::BackendUnavailable);
        }
        EXPECT_NO_THROW(gpu->sign_batch(b, kCtx, std::nullopt, nullptr));  // hedged по-прежнему работает
    }
}
