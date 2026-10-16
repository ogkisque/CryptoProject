#include <oqs/oqs.h>

#include <memory>

#include "vault/common/error.hpp"
#include "vault/common/thread_pool.hpp"
#include "vault/crypto/cpu_backends.hpp"

namespace vault::crypto {

namespace {

[[noreturn]] void fail(const char* what) { throw VaultError(ErrorCode::CryptoError, what); }

struct KemDeleter {
    void operator()(OQS_KEM* k) const { OQS_KEM_free(k); }
};

class CpuKemBackend final : public IKemBackend {
public:
    explicit CpuKemBackend(unsigned threads) : kem_(OQS_KEM_new(OQS_KEM_alg_ml_kem_768)) {
        if (threads > 1) pool_ = shared_thread_pool(threads);
        if (!kem_) fail("ML-KEM-768 is not available in liboqs");
        if (kem_->length_public_key != kMlKem768PublicKeySize ||
            kem_->length_secret_key != kMlKem768SecretKeySize ||
            kem_->length_ciphertext != kMlKem768CiphertextSize ||
            kem_->length_shared_secret != kMlKem768SharedSecretSize ||
            kem_->length_keypair_seed != kMlKem768KeygenSeedSize ||
            kem_->length_encaps_seed != kMlKem768EncapsSeedSize)
            fail("unexpected ML-KEM-768 parameter sizes");
    }

    std::string_view name() const override { return pool_ ? "cpu-mt" : "cpu"; }

    KemKeyPair keygen(std::optional<ByteView> seed) override {
        KemKeyPair kp{Bytes(kMlKem768PublicKeySize), SecureBytes(kMlKem768SecretKeySize)};
        keygen_into(kp.public_key.data(), kp.secret_key.data(), seed);
        return kp;
    }

    KemEncapsResult encaps(ByteView public_key, std::optional<ByteView> m) override {
        KemEncapsResult r{Bytes(kMlKem768CiphertextSize), SecureBytes(kMlKem768SharedSecretSize)};
        encaps_into(r.ciphertext.data(), r.shared_secret.data(), public_key, m);
        return r;
    }

    SecureBytes decaps(ByteView secret_key, ByteView ciphertext) override {
        SecureBytes ss(kMlKem768SharedSecretSize);
        decaps_into(ss.data(), secret_key, ciphertext);
        return ss;
    }

    void keygen_batch(std::size_t count, std::optional<ByteView> seeds, KemBatch& out,
                      TimingBreakdown* timing) override {
        if (seeds && seeds->size() != count * kMlKem768KeygenSeedSize) fail("keygen seeds size mismatch");
        auto t0 = now();
        out.count = count;
        out.public_keys.assign(count * kMlKem768PublicKeySize, 0);
        out.secret_keys = SecureBytes(count * kMlKem768SecretKeySize);
        for_each_index(count, [&](std::size_t i) {
            std::optional<ByteView> s;
            if (seeds) s = seeds->subspan(i * kMlKem768KeygenSeedSize, kMlKem768KeygenSeedSize);
            keygen_into(out.public_keys.data() + i * kMlKem768PublicKeySize,
                        out.secret_keys.data() + i * kMlKem768SecretKeySize, s);
        });
        record(timing, t0);
    }

    void encaps_batch(KemBatch& b, std::optional<ByteView> seeds, TimingBreakdown* timing) override {
        if (b.public_keys.size() != b.count * kMlKem768PublicKeySize) fail("public_keys size mismatch");
        if (seeds && seeds->size() != b.count * kMlKem768EncapsSeedSize) fail("encaps seeds size mismatch");
        auto t0 = now();
        b.ciphertexts.assign(b.count * kMlKem768CiphertextSize, 0);
        b.shared_secrets = SecureBytes(b.count * kMlKem768SharedSecretSize);
        for_each_index(b.count, [&](std::size_t i) {
            std::optional<ByteView> s;
            if (seeds) s = seeds->subspan(i * kMlKem768EncapsSeedSize, kMlKem768EncapsSeedSize);
            encaps_into(b.ciphertexts.data() + i * kMlKem768CiphertextSize,
                        b.shared_secrets.data() + i * kMlKem768SharedSecretSize,
                        ByteView(b.public_keys).subspan(i * kMlKem768PublicKeySize, kMlKem768PublicKeySize), s);
        });
        record(timing, t0);
    }

    void decaps_batch(KemBatch& b, TimingBreakdown* timing) override {
        if (b.secret_keys.size() != b.count * kMlKem768SecretKeySize) fail("secret_keys size mismatch");
        if (b.ciphertexts.size() != b.count * kMlKem768CiphertextSize) fail("ciphertexts size mismatch");
        auto t0 = now();
        b.shared_secrets = SecureBytes(b.count * kMlKem768SharedSecretSize);
        for_each_index(b.count, [&](std::size_t i) {
            decaps_into(b.shared_secrets.data() + i * kMlKem768SharedSecretSize,
                        b.secret_keys.view().subspan(i * kMlKem768SecretKeySize, kMlKem768SecretKeySize),
                        ByteView(b.ciphertexts).subspan(i * kMlKem768CiphertextSize, kMlKem768CiphertextSize));
        });
        record(timing, t0);
    }

private:
    // Независимые операции раздаются смежными диапазонами (по 4 на поток) — каждая элемент-операция
    // пишет только в свои срезы выходных буферов.
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
    static Clock::time_point now() { return Clock::now(); }
    static void record(TimingBreakdown* t, Clock::time_point t0) {
        if (!t) return;
        double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        t->kernel_ms += ms;
        t->total_ms += ms;
    }

    void keygen_into(std::uint8_t* pk, std::uint8_t* sk, std::optional<ByteView> seed) {
        OQS_STATUS st;
        if (seed) {
            if (seed->size() != kMlKem768KeygenSeedSize) fail("ML-KEM keygen seed must be 64 bytes");
            st = OQS_KEM_keypair_derand(kem_.get(), pk, sk, seed->data());
        } else {
            st = OQS_KEM_keypair(kem_.get(), pk, sk);
        }
        if (st != OQS_SUCCESS) fail("ML-KEM keygen failed");
    }

    void encaps_into(std::uint8_t* ct, std::uint8_t* ss, ByteView pk, std::optional<ByteView> m) {
        if (pk.size() != kMlKem768PublicKeySize) fail("bad ML-KEM public key size");
        OQS_STATUS st;
        if (m) {
            if (m->size() != kMlKem768EncapsSeedSize) fail("ML-KEM encaps seed must be 32 bytes");
            st = OQS_KEM_encaps_derand(kem_.get(), ct, ss, pk.data(), m->data());
        } else {
            st = OQS_KEM_encaps(kem_.get(), ct, ss, pk.data());
        }
        if (st != OQS_SUCCESS) fail("ML-KEM encaps failed");
    }

    void decaps_into(std::uint8_t* ss, ByteView sk, ByteView ct) {
        if (sk.size() != kMlKem768SecretKeySize) fail("bad ML-KEM secret key size");
        if (ct.size() != kMlKem768CiphertextSize) fail("bad ML-KEM ciphertext size");
        if (OQS_KEM_decaps(kem_.get(), ss, ct.data(), sk.data()) != OQS_SUCCESS) fail("ML-KEM decaps failed");
    }

    std::unique_ptr<OQS_KEM, KemDeleter> kem_;
    std::shared_ptr<ThreadPool> pool_;
};

}  // namespace

std::shared_ptr<IKemBackend> make_cpu_kem_backend(unsigned threads) {
    return std::make_shared<CpuKemBackend>(threads);
}

}  // namespace vault::crypto
