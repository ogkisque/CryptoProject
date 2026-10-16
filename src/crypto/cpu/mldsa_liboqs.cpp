// ML-DSA-65 на liboqs. Публичный API liboqs не даёт детерминированных keygen/sign,
// поэтому для режима с seed/rnd (тесты, ACVP, сравнение CPU==GPU) используются
// внутренние точки mldsa-native, экспортируемые из liboqs.a (портативный C-вариант).
// Производственный путь (seed/rnd = nullopt) идёт только через публичный API.
#include <oqs/oqs.h>

#include <chrono>
#include <memory>

#include "vault/common/error.hpp"
#include "vault/common/thread_pool.hpp"
#include "vault/crypto/cpu_backends.hpp"

extern "C" {
int PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
int PQCP_MLDSA_NATIVE_MLDSA65_C_signature_internal(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen,
                                                   const uint8_t* pre, size_t prelen, const uint8_t* rnd,
                                                   const uint8_t* sk, int externalmu);
}

namespace vault::crypto {

namespace {

[[noreturn]] void fail(const char* what) { throw VaultError(ErrorCode::CryptoError, what); }

struct SigDeleter {
    void operator()(OQS_SIG* s) const { OQS_SIG_free(s); }
};

class CpuSigBackend final : public ISigBackend {
public:
    explicit CpuSigBackend(unsigned threads) : sig_(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65)) {
        if (threads > 1) pool_ = shared_thread_pool(threads);
        if (!sig_) fail("ML-DSA-65 is not available in liboqs");
        if (sig_->length_public_key != kMlDsa65PublicKeySize || sig_->length_secret_key != kMlDsa65SecretKeySize ||
            sig_->length_signature != kMlDsa65SignatureSize || !sig_->sig_with_ctx_support)
            fail("unexpected ML-DSA-65 parameters");
    }

    std::string_view name() const override { return pool_ ? "cpu-mt" : "cpu"; }

    SigKeyPair keygen(std::optional<ByteView> seed) override {
        SigKeyPair kp{Bytes(kMlDsa65PublicKeySize), SecureBytes(kMlDsa65SecretKeySize)};
        keygen_into(kp.public_key.data(), kp.secret_key.data(), seed);
        return kp;
    }

    Bytes sign(ByteView sk, ByteView message, std::string_view ctx, std::optional<ByteView> rnd) override {
        Bytes sig(kMlDsa65SignatureSize);
        sign_into(sig.data(), sk, message, ctx, rnd);
        return sig;
    }

    bool verify(ByteView pk, ByteView message, std::string_view ctx, ByteView signature) override {
        if (pk.size() != kMlDsa65PublicKeySize || signature.size() != kMlDsa65SignatureSize ||
            ctx.size() > kMlDsaMaxContextSize)
            return false;
        return OQS_SIG_verify_with_ctx_str(sig_.get(), message.data(), message.size(), signature.data(),
                                           signature.size(), reinterpret_cast<const std::uint8_t*>(ctx.data()),
                                           ctx.size(), pk.data()) == OQS_SUCCESS;
    }

    void keygen_batch(std::size_t count, std::optional<ByteView> seeds, SigBatch& out,
                      TimingBreakdown* timing) override {
        if (seeds && seeds->size() != count * kMlDsa65KeygenSeedSize) fail("keygen seeds size mismatch");
        auto t0 = Clock::now();
        out.count = count;
        out.public_keys.assign(count * kMlDsa65PublicKeySize, 0);
        out.secret_keys = SecureBytes(count * kMlDsa65SecretKeySize);
        for_each_index(count, [&](std::size_t i) {
            std::optional<ByteView> s;
            if (seeds) s = seeds->subspan(i * kMlDsa65KeygenSeedSize, kMlDsa65KeygenSeedSize);
            keygen_into(out.public_keys.data() + i * kMlDsa65PublicKeySize,
                        out.secret_keys.data() + i * kMlDsa65SecretKeySize, s);
        });
        record(timing, t0);
    }

    void sign_batch(SigBatch& b, std::string_view ctx, std::optional<ByteView> rnds,
                    TimingBreakdown* timing) override {
        if (b.secret_keys.size() != b.count * kMlDsa65SecretKeySize) fail("secret_keys size mismatch");
        if (b.messages.size() != b.count * b.message_size) fail("messages size mismatch");
        if (rnds && rnds->size() != b.count * kMlDsa65SignRandSize) fail("rnds size mismatch");
        auto t0 = Clock::now();
        b.signatures.assign(b.count * kMlDsa65SignatureSize, 0);
        for_each_index(b.count, [&](std::size_t i) {
            std::optional<ByteView> r;
            if (rnds) r = rnds->subspan(i * kMlDsa65SignRandSize, kMlDsa65SignRandSize);
            sign_into(b.signatures.data() + i * kMlDsa65SignatureSize,
                      b.secret_keys.view().subspan(i * kMlDsa65SecretKeySize, kMlDsa65SecretKeySize),
                      ByteView(b.messages).subspan(i * b.message_size, b.message_size), ctx, r);
        });
        record(timing, t0);
    }

    void verify_batch(SigBatch& b, std::string_view ctx, TimingBreakdown* timing) override {
        if (b.public_keys.size() != b.count * kMlDsa65PublicKeySize) fail("public_keys size mismatch");
        if (b.messages.size() != b.count * b.message_size) fail("messages size mismatch");
        if (b.signatures.size() != b.count * kMlDsa65SignatureSize) fail("signatures size mismatch");
        auto t0 = Clock::now();
        b.verify_ok.assign(b.count, 0);
        for_each_index(b.count, [&](std::size_t i) {
            b.verify_ok[i] = verify(ByteView(b.public_keys).subspan(i * kMlDsa65PublicKeySize, kMlDsa65PublicKeySize),
                                    ByteView(b.messages).subspan(i * b.message_size, b.message_size), ctx,
                                    ByteView(b.signatures).subspan(i * kMlDsa65SignatureSize, kMlDsa65SignatureSize))
                                 ? 1
                                 : 0;
        });
        record(timing, t0);
    }

private:
    template <typename Fn>
    void for_each_index(std::size_t count, Fn&& fn) {
        if (!pool_ || count < 2) {
            for (std::size_t i = 0; i < count; ++i) fn(i);
            return;
        }
        std::size_t parts = std::min<std::size_t>(count, std::size_t{pool_->size()} * 4);
        pool_->parallel_for(parts, [&](std::size_t k) {
            for (std::size_t i = count * k / parts; i < count * (k + 1) / parts; ++i) fn(i);
        });
    }

    using Clock = std::chrono::steady_clock;
    static void record(TimingBreakdown* t, Clock::time_point t0) {
        if (!t) return;
        double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        t->kernel_ms += ms;
        t->total_ms += ms;
    }

    void keygen_into(std::uint8_t* pk, std::uint8_t* sk, std::optional<ByteView> seed) {
        if (seed) {
            if (seed->size() != kMlDsa65KeygenSeedSize) fail("ML-DSA keygen seed must be 32 bytes");
            if (PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal(pk, sk, seed->data()) != 0) fail("ML-DSA keygen failed");
        } else if (OQS_SIG_keypair(sig_.get(), pk, sk) != OQS_SUCCESS) {
            fail("ML-DSA keygen failed");
        }
    }

    void sign_into(std::uint8_t* out, ByteView sk, ByteView message, std::string_view ctx,
                   std::optional<ByteView> rnd) {
        if (sk.size() != kMlDsa65SecretKeySize) fail("bad ML-DSA secret key size");
        if (ctx.size() > kMlDsaMaxContextSize) fail("ML-DSA context too long");
        std::size_t len = 0;
        if (!rnd) {
            if (OQS_SIG_sign_with_ctx_str(sig_.get(), out, &len, message.data(), message.size(),
                                          reinterpret_cast<const std::uint8_t*>(ctx.data()), ctx.size(),
                                          sk.data()) != OQS_SUCCESS)
                fail("ML-DSA sign failed");
        } else {
            if (rnd->size() != kMlDsa65SignRandSize) fail("ML-DSA rnd must be 32 bytes");
            // FIPS 204, Algorithm 2: M' = 0x00 (pure) || len(ctx) || ctx || M
            Bytes pre;
            pre.push_back(0x00);
            pre.push_back(static_cast<std::uint8_t>(ctx.size()));
            pre.insert(pre.end(), ctx.begin(), ctx.end());
            if (PQCP_MLDSA_NATIVE_MLDSA65_C_signature_internal(out, &len, message.data(), message.size(), pre.data(),
                                                               pre.size(), rnd->data(), sk.data(), 0) != 0)
                fail("ML-DSA sign failed");
        }
        if (len != kMlDsa65SignatureSize) fail("unexpected ML-DSA signature length");
    }

    std::unique_ptr<OQS_SIG, SigDeleter> sig_;
    std::shared_ptr<ThreadPool> pool_;
};

}  // namespace

std::shared_ptr<ISigBackend> make_cpu_sig_backend(unsigned threads) {
    return std::make_shared<CpuSigBackend>(threads);
}

}  // namespace vault::crypto
