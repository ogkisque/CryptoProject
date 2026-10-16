// IKemBackend / ISigBackend поверх IMlKemRunner / IMlDsaRunner (этап 6): проверка размеров, порционирование,
// калибровка режима context string ML-DSA, сборка M'. Никакого CUDA — тестируется на CPU.
#include "host/pqc_backends.hpp"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <string>

#include "host/pqc_batch_plan.hpp"
#include "vault/common/error.hpp"

namespace vault::gpu {

namespace {

using Clock = std::chrono::steady_clock;
double ms_since(Clock::time_point t0) { return std::chrono::duration<double, std::milli>(Clock::now() - t0).count(); }

[[noreturn]] void bad_arg(const std::string& what) { throw VaultError(ErrorCode::InvalidArgument, what); }

void check(bool ok, const char* what) {
    if (!ok) bad_arg(what);
}

// ------------------------------------------------------------------ ML-KEM

class PqcKemBackend final : public crypto::IKemBackend {
public:
    explicit PqcKemBackend(std::unique_ptr<IMlKemRunner> r) : runner_(std::move(r)) {
        if (!runner_) bad_arg("pqc kem backend: runner is null");
    }

    std::string_view name() const override { return "gpu"; }

    crypto::KemKeyPair keygen(std::optional<ByteView> seed) override {
        crypto::KemBatch b;
        keygen_batch(1, seed, b, nullptr);
        crypto::KemKeyPair kp{std::move(b.public_keys), std::move(b.secret_keys)};
        return kp;
    }

    crypto::KemEncapsResult encaps(ByteView public_key, std::optional<ByteView> m) override {
        crypto::KemBatch b;
        b.count = 1;
        b.public_keys.assign(public_key.begin(), public_key.end());
        encaps_batch(b, m, nullptr);
        return crypto::KemEncapsResult{std::move(b.ciphertexts), std::move(b.shared_secrets)};
    }

    SecureBytes decaps(ByteView secret_key, ByteView ciphertext) override {
        crypto::KemBatch b;
        b.count = 1;
        b.secret_keys = SecureBytes(secret_key);
        b.ciphertexts.assign(ciphertext.begin(), ciphertext.end());
        decaps_batch(b, nullptr);
        return std::move(b.shared_secrets);
    }

    void keygen_batch(std::size_t count, std::optional<ByteView> seeds, crypto::KemBatch& out,
                      TimingBreakdown* timing) override {
        if (seeds) {
            check(seeds->size() == count * kMlKem768KeygenSeedSize, "ML-KEM keygen seeds size mismatch");
            require_seeds();
        }
        const auto t0 = Clock::now();
        TimingBreakdown tb;
        out.count = count;
        out.public_keys.assign(count * kMlKem768PublicKeySize, 0);
        out.secret_keys = SecureBytes(count * kMlKem768SecretKeySize);
        for (const PqcChunk& c : plan_pqc_chunks(count, runner_->keygen_item_bytes(), runner_->max_chunk_bytes()))
            runner_->keygen(c.count, seeds ? seeds->data() + c.first * kMlKem768KeygenSeedSize : nullptr,
                            out.public_keys.data() + c.first * kMlKem768PublicKeySize,
                            out.secret_keys.data() + c.first * kMlKem768SecretKeySize, tb);
        finish(tb, t0, timing);
    }

    void encaps_batch(crypto::KemBatch& b, std::optional<ByteView> seeds, TimingBreakdown* timing) override {
        check(b.public_keys.size() == b.count * kMlKem768PublicKeySize, "public_keys size mismatch");
        if (seeds) {
            check(seeds->size() == b.count * kMlKem768EncapsSeedSize, "ML-KEM encaps seeds size mismatch");
            require_seeds();
        }
        const auto t0 = Clock::now();
        TimingBreakdown tb;
        b.ciphertexts.assign(b.count * kMlKem768CiphertextSize, 0);
        b.shared_secrets = SecureBytes(b.count * kMlKem768SharedSecretSize);
        for (const PqcChunk& c : plan_pqc_chunks(b.count, runner_->encaps_item_bytes(), runner_->max_chunk_bytes()))
            runner_->encaps(c.count, b.public_keys.data() + c.first * kMlKem768PublicKeySize,
                            seeds ? seeds->data() + c.first * kMlKem768EncapsSeedSize : nullptr,
                            b.ciphertexts.data() + c.first * kMlKem768CiphertextSize,
                            b.shared_secrets.data() + c.first * kMlKem768SharedSecretSize, tb);
        finish(tb, t0, timing);
    }

    void decaps_batch(crypto::KemBatch& b, TimingBreakdown* timing) override {
        check(b.secret_keys.size() == b.count * kMlKem768SecretKeySize, "secret_keys size mismatch");
        check(b.ciphertexts.size() == b.count * kMlKem768CiphertextSize, "ciphertexts size mismatch");
        const auto t0 = Clock::now();
        TimingBreakdown tb;
        b.shared_secrets = SecureBytes(b.count * kMlKem768SharedSecretSize);
        for (const PqcChunk& c : plan_pqc_chunks(b.count, runner_->decaps_item_bytes(), runner_->max_chunk_bytes()))
            runner_->decaps(c.count, b.secret_keys.data() + c.first * kMlKem768SecretKeySize,
                            b.ciphertexts.data() + c.first * kMlKem768CiphertextSize,
                            b.shared_secrets.data() + c.first * kMlKem768SharedSecretSize, tb);
        finish(tb, t0, timing);
    }

private:
    void require_seeds() const {
        if (!runner_->supports_seeds())
            throw VaultError(ErrorCode::BackendUnavailable,
                             "gpu ML-KEM: caller-supplied entropy is not supported by this cuPQC build (entropy layout not "
                             "compatible with FIPS 203 inputs)");
    }
    static void finish(TimingBreakdown& tb, Clock::time_point t0, TimingBreakdown* timing) {
        tb.total_ms = ms_since(t0);
        if (timing) *timing += tb;
    }

    std::unique_ptr<IMlKemRunner> runner_;
};

// ------------------------------------------------------------------ ML-DSA

class PqcSigBackend final : public crypto::ISigBackend {
public:
    PqcSigBackend(std::unique_ptr<IMlDsaRunner> r, std::shared_ptr<crypto::ISigBackend> cpu)
        : runner_(std::move(r)), cpu_(std::move(cpu)) {
        if (!runner_ || !cpu_) bad_arg("pqc sig backend: runner and cpu reference are required");
    }

    std::string_view name() const override { return "gpu"; }

    SigContextMode mode() {
        std::lock_guard<std::mutex> lk(mu_);
        if (mode_ == SigContextMode::Unknown) mode_ = calibrate();
        return mode_;
    }

    crypto::SigKeyPair keygen(std::optional<ByteView> seed) override {
        crypto::SigBatch b;
        keygen_batch(1, seed, b, nullptr);
        return crypto::SigKeyPair{std::move(b.public_keys), std::move(b.secret_keys)};
    }

    // Одиночные операции (в vault — по одной на команду): если GPU не умеет такой context string, подпись/проверка
    // идёт на CPU (в отличие от batch, где это ошибка BackendUnavailable).
    Bytes sign(ByteView secret_key, ByteView message, std::string_view context, std::optional<ByteView> rnd) override {
        if (!ctx_supported(context)) return cpu_->sign(secret_key, message, context, rnd);
        crypto::SigBatch b;
        b.count = 1;
        b.message_size = message.size();
        b.secret_keys = SecureBytes(secret_key);
        b.messages.assign(message.begin(), message.end());
        sign_batch(b, context, rnd, nullptr);
        return std::move(b.signatures);
    }

    bool verify(ByteView public_key, ByteView message, std::string_view context, ByteView signature) override {
        if (public_key.size() != kMlDsa65PublicKeySize || signature.size() != kMlDsa65SignatureSize ||
            context.size() > kMlDsaMaxContextSize)
            return false;  // как у CPU-backend'а: неверная длина — не исключение
        if (!ctx_supported(context)) return cpu_->verify(public_key, message, context, signature);
        crypto::SigBatch b;
        b.count = 1;
        b.message_size = message.size();
        b.public_keys.assign(public_key.begin(), public_key.end());
        b.messages.assign(message.begin(), message.end());
        b.signatures.assign(signature.begin(), signature.end());
        verify_batch(b, context, nullptr);
        return b.verify_ok.at(0) == 1;
    }

    void keygen_batch(std::size_t count, std::optional<ByteView> seeds, crypto::SigBatch& out,
                      TimingBreakdown* timing) override {
        if (seeds) {
            check(seeds->size() == count * kMlDsa65KeygenSeedSize, "ML-DSA keygen seeds size mismatch");
            require_seeds();
        }
        const auto t0 = Clock::now();
        TimingBreakdown tb;
        out.count = count;
        out.public_keys.assign(count * kMlDsa65PublicKeySize, 0);
        out.secret_keys = SecureBytes(count * kMlDsa65SecretKeySize);
        for (const PqcChunk& c : plan_pqc_chunks(count, runner_->keygen_item_bytes(), runner_->max_chunk_bytes()))
            runner_->keygen(c.count, seeds ? seeds->data() + c.first * kMlDsa65KeygenSeedSize : nullptr,
                            out.public_keys.data() + c.first * kMlDsa65PublicKeySize,
                            out.secret_keys.data() + c.first * kMlDsa65SecretKeySize, tb);
        finish(tb, t0, timing);
    }

    void sign_batch(crypto::SigBatch& b, std::string_view context, std::optional<ByteView> rnds,
                    TimingBreakdown* timing) override {
        check(b.secret_keys.size() == b.count * kMlDsa65SecretKeySize, "secret_keys size mismatch");
        check(b.messages.size() == b.count * b.message_size, "messages size mismatch");
        if (rnds) {
            check(rnds->size() == b.count * kMlDsa65SignRandSize, "rnds size mismatch");
            require_seeds();
        }
        require_ctx(context);
        const auto t0 = Clock::now();
        TimingBreakdown tb;
        const Bytes wrapped = wrap_messages(b.messages, b.count, b.message_size, context);
        const std::size_t wsize = wrapped_size(b.message_size, context);
        b.signatures.assign(b.count * kMlDsa65SignatureSize, 0);
        for (const PqcChunk& c : plan_pqc_chunks(b.count, runner_->sign_item_bytes(wsize), runner_->max_chunk_bytes()))
            runner_->sign(c.count, b.secret_keys.data() + c.first * kMlDsa65SecretKeySize,
                          wrapped.data() + c.first * wsize, wsize,
                          rnds ? rnds->data() + c.first * kMlDsa65SignRandSize : nullptr,
                          b.signatures.data() + c.first * kMlDsa65SignatureSize, tb);
        finish(tb, t0, timing);
    }

    void verify_batch(crypto::SigBatch& b, std::string_view context, TimingBreakdown* timing) override {
        check(b.public_keys.size() == b.count * kMlDsa65PublicKeySize, "public_keys size mismatch");
        check(b.messages.size() == b.count * b.message_size, "messages size mismatch");
        check(b.signatures.size() == b.count * kMlDsa65SignatureSize, "signatures size mismatch");
        require_ctx(context);
        const auto t0 = Clock::now();
        TimingBreakdown tb;
        const Bytes wrapped = wrap_messages(b.messages, b.count, b.message_size, context);
        const std::size_t wsize = wrapped_size(b.message_size, context);
        b.verify_ok.assign(b.count, 0);
        for (const PqcChunk& c : plan_pqc_chunks(b.count, runner_->verify_item_bytes(wsize), runner_->max_chunk_bytes()))
            runner_->verify(c.count, b.public_keys.data() + c.first * kMlDsa65PublicKeySize,
                            wrapped.data() + c.first * wsize, wsize,
                            b.signatures.data() + c.first * kMlDsa65SignatureSize, b.verify_ok.data() + c.first, tb);
        finish(tb, t0, timing);
    }

private:
    void require_seeds() const {
        if (!runner_->supports_seeds())
            throw VaultError(ErrorCode::BackendUnavailable,
                             "gpu ML-DSA: caller-supplied entropy is not supported by this cuPQC build (entropy layout not "
                             "compatible with FIPS 204 inputs)");
    }
    static void finish(TimingBreakdown& tb, Clock::time_point t0, TimingBreakdown* timing) {
        tb.total_ms = ms_since(t0);
        if (timing) *timing += tb;
    }

    bool ctx_supported(std::string_view context) {
        if (context.size() > kMlDsaMaxContextSize) bad_arg("ML-DSA context too long");
        switch (mode()) {
            case SigContextMode::Internal: return true;
            case SigContextMode::PureEmptyContext: return context.empty();
            default: return false;
        }
    }

    void require_ctx(std::string_view context) {
        if (ctx_supported(context)) return;
        const SigContextMode m = mode();
        throw VaultError(ErrorCode::BackendUnavailable,
                         m == SigContextMode::PureEmptyContext
                             ? "gpu ML-DSA: this cuPQC build signs only with an empty context string (use the cpu backend "
                               "for the vault manifest context)"
                             : "gpu ML-DSA: signatures from cuPQC are not compatible with liboqs (FIPS 204 pure ML-DSA)");
    }

    // Internal: каждому сообщению предшествует M' = 0x00 || len(ctx) || ctx. PureEmptyContext: сообщение как есть.
    std::size_t wrapped_size(std::size_t message_size, std::string_view context) {
        return mode() == SigContextMode::Internal ? message_size + 2 + context.size() : message_size;
    }
    Bytes wrap_messages(const Bytes& msgs, std::size_t count, std::size_t message_size, std::string_view context) {
        if (mode() != SigContextMode::Internal) return msgs;
        const std::size_t w = message_size + 2 + context.size();
        Bytes out(count * w);
        for (std::size_t i = 0; i < count; ++i) {
            std::uint8_t* p = out.data() + i * w;
            p[0] = 0x00;  // pure ML-DSA (не HashML-DSA)
            p[1] = static_cast<std::uint8_t>(context.size());
            std::copy(context.begin(), context.end(), p + 2);
            std::copy_n(msgs.begin() + static_cast<std::ptrdiff_t>(i * message_size), message_size, p + 2 + context.size());
        }
        return out;
    }

    // Калибровка (один раз): документация cuPQC не говорит, что именно подписывается и есть ли context string.
    // Подписываем X = {0, 0} || M и смотрим, какой liboqs-проверкой подпись проходит:
    //   verify(M, ctx = "")  -> cuPQC подписал X как M' (Sign_internal)            => Internal
    //   verify(X, ctx = "")  -> cuPQC подписал X как сообщение «pure» с пустым ctx => PureEmptyContext
    // Затем проверяется обратное направление (liboqs-подпись -> cuPQC verify) и отвержение порченой подписи.
    SigContextMode calibrate() {
        constexpr std::string_view kCtx = "edu-vault-manifest-v1";
        TimingBreakdown tb;
        const crypto::SigKeyPair kp = cpu_->keygen(std::nullopt);
        Bytes m(kManifestV1Size);
        for (std::size_t i = 0; i < m.size(); ++i) m[i] = static_cast<std::uint8_t>(i * 7 + 3);
        Bytes x;
        x.reserve(2 + m.size());
        x.push_back(0x00);
        x.push_back(0x00);
        for (std::uint8_t byte : m) x.push_back(byte);

        Bytes sig(kMlDsa65SignatureSize);
        runner_->sign(1, kp.secret_key.data(), x.data(), x.size(), nullptr, sig.data(), tb);
        SigContextMode mode = SigContextMode::Unusable;
        if (cpu_->verify(kp.public_key, m, "", sig)) mode = SigContextMode::Internal;
        else if (cpu_->verify(kp.public_key, x, "", sig)) mode = SigContextMode::PureEmptyContext;
        if (mode == SigContextMode::Unusable) return mode;

        auto gpu_verify = [&](const Bytes& msg, const Bytes& s) {
            std::uint8_t ok = 0;
            runner_->verify(1, kp.public_key.data(), msg.data(), msg.size(), s.data(), &ok, tb);
            return ok == 1;
        };
        Bytes cpu_sig, probe;
        if (mode == SigContextMode::Internal) {
            cpu_sig = cpu_->sign(kp.secret_key.view(), m, kCtx, std::nullopt);
            probe.reserve(2 + kCtx.size() + m.size());
            probe.push_back(0x00);
            probe.push_back(static_cast<std::uint8_t>(kCtx.size()));
            for (char ch : kCtx) probe.push_back(static_cast<std::uint8_t>(ch));
            for (std::uint8_t byte : m) probe.push_back(byte);
        } else {
            cpu_sig = cpu_->sign(kp.secret_key.view(), m, "", std::nullopt);
            probe = m;
        }
        Bytes corrupted = cpu_sig;
        corrupted[100] ^= 1;
        if (!gpu_verify(probe, cpu_sig) || gpu_verify(probe, corrupted)) return SigContextMode::Unusable;
        return mode;
    }

    std::unique_ptr<IMlDsaRunner> runner_;
    std::shared_ptr<crypto::ISigBackend> cpu_;
    std::mutex mu_;
    SigContextMode mode_ = SigContextMode::Unknown;
};

}  // namespace

std::shared_ptr<crypto::IKemBackend> make_pqc_kem_backend(std::unique_ptr<IMlKemRunner> runner) {
    return std::make_shared<PqcKemBackend>(std::move(runner));
}

std::shared_ptr<crypto::ISigBackend> make_pqc_sig_backend(std::unique_ptr<IMlDsaRunner> runner,
                                                         std::shared_ptr<crypto::ISigBackend> cpu_reference) {
    return std::make_shared<PqcSigBackend>(std::move(runner), std::move(cpu_reference));
}

SigContextMode sig_context_mode(crypto::ISigBackend& backend) {
    auto* b = dynamic_cast<PqcSigBackend*>(&backend);
    if (!b) bad_arg("sig_context_mode: not a pqc sig backend");
    return b->mode();
}

}  // namespace vault::gpu
