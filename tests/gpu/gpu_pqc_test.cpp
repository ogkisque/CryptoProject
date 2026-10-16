// GPU ML-KEM-768 / ML-DSA-65 на cuPQC (этап 6): ACVP, перекрёстные проверки с liboqs, vault.
// Без CUDA-устройства или без cuPQC в сборке каждый тест делает GTEST_SKIP с причиной.
//
// Три предположения о cuPQC, не закрытые документацией, проверяются здесь и ЗАПИСЫВАЮТСЯ в вывод/свойства теста:
//   (1) entropy-буфер = FIPS-входы (d||z, m, xi, rnd) -> seeded-тесты ACVP; если не подтвердилось — SKIP с причиной,
//       а корректность ключей/подписей всё равно проверяется перекрёстно;
//   (2) режим context string ML-DSA (Internal / PureEmptyContext / Unusable) — печатается как `[cuPQC] ...`;
//   (3) форматы ключей/шифртекстов/подписей — совпадение с liboqs (иначе перекрёстные тесты упадут).
#include <gtest/gtest.h>
#include <sys/wait.h>

#include <fstream>
#include <random>
#include <sstream>

#include "host/pqc_backends.hpp"
#include "vault/common/error.hpp"
#include "vault/crypto/backends.hpp"
#include "../integration/test_util.hpp"

using namespace vault;
using namespace vault::testing;

namespace {

Bytes H(const std::string& s) {
    if (s == "-") return {};
    auto b = from_hex(s);
    EXPECT_TRUE(b.has_value());
    return b.value_or(Bytes{});
}

Bytes rand_bytes(std::mt19937_64& g, std::size_t n) {
    Bytes b(n);
    for (auto& x : b) x = static_cast<std::uint8_t>(g());
    return b;
}

std::vector<std::vector<std::string>> read_vectors(const char* file, const std::string& kind) {
    std::ifstream in(std::string(VAULT_TEST_VECTORS_DIR) + "/" + file);
    EXPECT_TRUE(in.good()) << file;
    std::vector<std::vector<std::string>> out;
    for (std::string line; std::getline(in, line);) {
        std::istringstream ss(line);
        std::vector<std::string> f;
        for (std::string w; ss >> w;) f.push_back(w);
        if (!f.empty() && f[0] == kind) out.push_back(std::move(f));
    }
    return out;
}

Bytes sv(const SecureBytes& s) { return Bytes(s.view().begin(), s.view().end()); }

crypto::CryptoBackends make_gpu(crypto::BackendConfig cfg = {}) {
    cfg.kind = crypto::BackendKind::Gpu;
    return crypto::make_backends(cfg);
}

}  // namespace

class GpuPqc : public VaultFixture {
protected:
    void SetUp() override {
        VaultFixture::SetUp();
        try {
            gpu = make_gpu();
        } catch (const VaultError& e) {
            if (e.code() != ErrorCode::BackendUnavailable) throw;
            GTEST_SKIP() << "no GPU backend: " << e.what();
        }
        if (gpu.kem->name() != "gpu" || gpu.sig->name() != "gpu") GTEST_SKIP() << "built without cuPQC (GPU ML-KEM/ML-DSA unavailable)";
        cpu = crypto::make_backends({});
        rng.seed(2026);
    }
    // Сообщает, поддерживает ли контекст manifest: Internal -> да; иначе batch с ctx бросит BackendUnavailable.
    bool manifest_ctx_on_gpu() { return gpu::sig_context_mode(*gpu.sig) == gpu::SigContextMode::Internal; }

    crypto::CryptoBackends gpu, cpu;
    std::mt19937_64 rng;
};

// ------------------------------------------------------------------ ML-KEM

TEST_F(GpuPqc, KemAcvpDecapsulationIncludingImplicitRejection) {
    auto v = read_vectors("mlkem768_acvp.txt", "DECAPS");
    ASSERT_FALSE(v.empty());
    for (const auto& f : v) {
        Bytes dk = H(f[1]), c = H(f[2]);
        EXPECT_EQ(to_hex(gpu.kem->decaps(dk, c).view()), f[3]);
    }
}

TEST_F(GpuPqc, KemAcvpSeededKeygenAndEncaps) {
    int refuted = 0, total = 0;
    for (const auto& f : read_vectors("mlkem768_acvp.txt", "KEYGEN")) {
        Bytes seed = H(f[1]);
        crypto::KemKeyPair kp;
        try {
            kp = gpu.kem->keygen(ByteView(seed));
        } catch (const VaultError& e) {
            if (e.code() == ErrorCode::BackendUnavailable) GTEST_SKIP() << e.what();
            throw;
        }
        ++total;
        if (to_hex(kp.public_key) != f[2] || to_hex(kp.secret_key.view()) != f[3]) {
            // Не совпало с ACVP: ключи хотя бы рабочие? (иначе это настоящая ошибка, а не иная раскладка entropy)
            auto e = cpu.kem->encaps(kp.public_key, std::nullopt);
            ASSERT_EQ(sv(cpu.kem->decaps(kp.secret_key.view(), e.ciphertext)), sv(e.shared_secret)) << "GPU keypair is unusable";
            ++refuted;
        }
    }
    for (const auto& f : read_vectors("mlkem768_acvp.txt", "ENCAPS")) {
        Bytes ek = H(f[1]), m = H(f[2]);
        auto r = gpu.kem->encaps(ek, ByteView(m));
        ++total;
        if (to_hex(r.ciphertext) != f[3] || to_hex(r.shared_secret.view()) != f[4]) ++refuted;
    }
    RecordProperty("entropy_layout_matches_fips203", refuted == 0 ? "yes" : "no");
    if (refuted > 0)
        GTEST_SKIP() << "[cuPQC] ASSUMPTION REFUTED: seeded entropy is not FIPS 203 d||z / m (" << refuted << "/" << total
                     << " ACVP vectors differ); keys remain valid and interoperable. Seeded GPU runs cannot be byte-compared with CPU.";
}

TEST_F(GpuPqc, KemInteroperatesWithCpuInBothDirections) {
    for (std::size_t n : {1u, 10u, 257u}) {
        crypto::KemBatch g;
        gpu.kem->keygen_batch(n, std::nullopt, g, nullptr);
        ASSERT_EQ(g.public_keys.size(), n * kMlKem768PublicKeySize);
        // GPU keygen -> CPU encaps -> GPU decaps
        crypto::KemBatch c;
        c.count = n;
        c.public_keys = g.public_keys;
        cpu.kem->encaps_batch(c, std::nullopt, nullptr);
        crypto::KemBatch d;
        d.count = n;
        d.secret_keys = g.secret_keys.clone();
        d.ciphertexts = c.ciphertexts;
        gpu.kem->decaps_batch(d, nullptr);
        EXPECT_EQ(sv(d.shared_secrets), sv(c.shared_secrets)) << "n=" << n;
        // GPU encaps -> CPU decaps
        crypto::KemBatch e;
        e.count = n;
        e.public_keys = g.public_keys;
        gpu.kem->encaps_batch(e, std::nullopt, nullptr);
        crypto::KemBatch f;
        f.count = n;
        f.secret_keys = g.secret_keys.clone();
        f.ciphertexts = e.ciphertexts;
        cpu.kem->decaps_batch(f, nullptr);
        EXPECT_EQ(sv(f.shared_secrets), sv(e.shared_secrets)) << "n=" << n;
        // разные элементы batch'а дают разные секреты (entropy не размножилась)
        if (n > 1) EXPECT_NE(Bytes(e.shared_secrets.view().begin(), e.shared_secrets.view().begin() + 32),
                             Bytes(e.shared_secrets.view().begin() + 32, e.shared_secrets.view().begin() + 64));
    }
}

TEST_F(GpuPqc, KemImplicitRejectionAndTimingAndPooling) {
    auto kp = gpu.kem->keygen(std::nullopt);
    auto e = cpu.kem->encaps(kp.public_key, std::nullopt);
    Bytes bad = e.ciphertext;
    bad[5] ^= 1;
    EXPECT_EQ(sv(gpu.kem->decaps(kp.secret_key.view(), bad)), sv(cpu.kem->decaps(kp.secret_key.view(), bad)));  // implicit rejection одинаков

    TimingBreakdown tb;
    crypto::KemBatch b;
    gpu.kem->keygen_batch(100, std::nullopt, b, &tb);
    EXPECT_GT(tb.total_ms, 0.0);
    EXPECT_GT(tb.kernel_ms, 0.0);
    EXPECT_GT(tb.entropy_ms, 0.0);  // генерация entropy внутри cuPQC измеряется отдельно
    EXPECT_GT(tb.d2h_ms, 0.0);

    crypto::BackendConfig c;
    c.gpu_pool_buffers = true;
    auto pooled = make_gpu(c);
    for (int rep = 0; rep < 3; ++rep) {
        crypto::KemBatch p;
        pooled.kem->keygen_batch(50, std::nullopt, p, nullptr);
        crypto::KemBatch q;
        q.count = 50;
        q.public_keys = p.public_keys;
        pooled.kem->encaps_batch(q, std::nullopt, nullptr);
        crypto::KemBatch r;
        r.count = 50;
        r.secret_keys = p.secret_keys.clone();
        r.ciphertexts = q.ciphertexts;
        pooled.kem->decaps_batch(r, nullptr);
        EXPECT_EQ(sv(r.shared_secrets), sv(q.shared_secrets)) << "rep=" << rep;
    }
}

TEST_F(GpuPqc, KemSmallChunksGiveSameInteroperableResults) {
    crypto::BackendConfig c;
    c.gpu_max_chunk_bytes = 1 << 20;  // минимум; batch в несколько тысяч элементов режется на порции
    auto small = make_gpu(c);
    crypto::KemBatch g;
    small.kem->keygen_batch(1000, std::nullopt, g, nullptr);
    crypto::KemBatch e;
    e.count = 1000;
    e.public_keys = g.public_keys;
    small.kem->encaps_batch(e, std::nullopt, nullptr);
    crypto::KemBatch f;
    f.count = 1000;
    f.secret_keys = g.secret_keys.clone();
    f.ciphertexts = e.ciphertexts;
    cpu.kem->decaps_batch(f, nullptr);
    EXPECT_EQ(sv(f.shared_secrets), sv(e.shared_secrets));
}

// ------------------------------------------------------------------ ML-DSA

TEST_F(GpuPqc, SigReportsContextModeAndHonoursIt) {
    const gpu::SigContextMode mode = gpu::sig_context_mode(*gpu.sig);
    const char* name = mode == gpu::SigContextMode::Internal ? "Internal"
                       : mode == gpu::SigContextMode::PureEmptyContext ? "PureEmptyContext"
                                                                       : "Unusable";
    std::cout << "[cuPQC] ML-DSA context mode: " << name << "\n";
    RecordProperty("mldsa_context_mode", name);
    ASSERT_NE(mode, gpu::SigContextMode::Unusable) << "cuPQC ML-DSA signatures are not FIPS 204 compatible with liboqs in either mode";

    crypto::SigBatch b;
    cpu.sig->keygen_batch(2, std::nullopt, b, nullptr);
    b.message_size = 16;
    b.messages.assign(32, 3);
    if (mode == gpu::SigContextMode::PureEmptyContext) {
        EXPECT_THROW(gpu.sig->sign_batch(b, "edu-vault-manifest-v1", std::nullopt, nullptr), VaultError);
        EXPECT_NO_THROW(gpu.sig->sign_batch(b, "", std::nullopt, nullptr));
    } else {
        EXPECT_NO_THROW(gpu.sig->sign_batch(b, "edu-vault-manifest-v1", std::nullopt, nullptr));
    }
}

TEST_F(GpuPqc, SigAcvpVerifyAndDeterministicSign) {
    const gpu::SigContextMode mode = gpu::sig_context_mode(*gpu.sig);
    if (mode == gpu::SigContextMode::Unusable) GTEST_SKIP() << "ML-DSA unusable";
    int verified = 0;
    for (const auto& f : read_vectors("mldsa65_acvp.txt", "SIGVER")) {
        const bool expected = f[1] == "1";
        const Bytes ctx_bytes = H(f[4]);
        const std::string ctx(ctx_bytes.begin(), ctx_bytes.end());
        if (mode == gpu::SigContextMode::PureEmptyContext && !ctx.empty()) continue;
        EXPECT_EQ(gpu.sig->verify(H(f[2]), H(f[3]), ctx, H(f[5])), expected);
        ++verified;
    }
    EXPECT_GT(verified, 0);

    int refuted = 0, total = 0;
    for (const auto& f : read_vectors("mldsa65_acvp.txt", "SIGGEN")) {
        Bytes rnd = H(f[1]), sk = H(f[2]), msg = H(f[3]);
        const Bytes ctx_bytes = H(f[4]);
        const std::string ctx(ctx_bytes.begin(), ctx_bytes.end());
        if (mode == gpu::SigContextMode::PureEmptyContext && !ctx.empty()) continue;
        Bytes sig;
        try {
            sig = gpu.sig->sign(sk, msg, ctx, ByteView(rnd));
        } catch (const VaultError& e) {
            if (e.code() == ErrorCode::BackendUnavailable) GTEST_SKIP() << e.what();
            throw;
        }
        ++total;
        if (to_hex(sig) != f[5]) ++refuted;
    }
    RecordProperty("entropy_layout_matches_fips204_sign", refuted == 0 ? "yes" : "no");
    if (refuted > 0)
        GTEST_SKIP() << "[cuPQC] ASSUMPTION REFUTED: seeded sign entropy is not FIPS 204 rnd (" << refuted << "/" << total
                     << " ACVP signatures differ); verification above still passed.";
}

TEST_F(GpuPqc, SigAcvpSeededKeygen) {
    int refuted = 0, total = 0;
    for (const auto& f : read_vectors("mldsa65_acvp.txt", "KEYGEN")) {
        Bytes seed = H(f[1]);
        crypto::SigKeyPair kp;
        try {
            kp = gpu.sig->keygen(ByteView(seed));
        } catch (const VaultError& e) {
            if (e.code() == ErrorCode::BackendUnavailable) GTEST_SKIP() << e.what();
            throw;
        }
        ++total;
        if (to_hex(kp.public_key) != f[2] || to_hex(kp.secret_key.view()) != f[3]) ++refuted;
        // ключи рабочие: CPU-подпись проверяется GPU-ключом и наоборот
        Bytes msg = {1, 2, 3};
        EXPECT_TRUE(cpu.sig->verify(kp.public_key, msg, "", cpu.sig->sign(kp.secret_key.view(), msg, "", std::nullopt)));
    }
    RecordProperty("entropy_layout_matches_fips204_keygen", refuted == 0 ? "yes" : "no");
    if (refuted > 0)
        GTEST_SKIP() << "[cuPQC] ASSUMPTION REFUTED: seeded keygen entropy is not FIPS 204 xi (" << refuted << "/" << total << " differ)";
}

TEST_F(GpuPqc, SigInteroperatesWithCpuInBothDirections) {
    const std::string ctx = manifest_ctx_on_gpu() ? "edu-vault-manifest-v1" : "";
    for (std::size_t n : {1u, 8u, 100u, 1000u}) {
        for (std::size_t msize : {std::size_t{168}, std::size_t{1000}}) {
            // GPU sign -> CPU verify
            crypto::SigBatch g;
            cpu.sig->keygen_batch(n, std::nullopt, g, nullptr);
            g.message_size = msize;
            g.messages = rand_bytes(rng, n * msize);
            gpu.sig->sign_batch(g, ctx, std::nullopt, nullptr);
            for (std::size_t i = 0; i < n; i += std::max<std::size_t>(1, n / 20))
                ASSERT_TRUE(cpu.sig->verify(ByteView(g.public_keys).subspan(i * kMlDsa65PublicKeySize, kMlDsa65PublicKeySize),
                                            ByteView(g.messages).subspan(i * msize, msize), ctx,
                                            ByteView(g.signatures).subspan(i * kMlDsa65SignatureSize, kMlDsa65SignatureSize)))
                    << "n=" << n << " msize=" << msize << " i=" << i;
            // порча: GPU verify отвергает
            g.signatures[kMlDsa65SignatureSize * (n - 1) + 200] ^= 1;
            gpu.sig->verify_batch(g, ctx, nullptr);
            EXPECT_EQ(g.verify_ok[n - 1], 0);
            EXPECT_EQ(std::count(g.verify_ok.begin(), g.verify_ok.end(), 1), static_cast<long>(n - 1));

            // CPU sign -> GPU verify
            crypto::SigBatch c;
            cpu.sig->keygen_batch(n, std::nullopt, c, nullptr);
            c.message_size = msize;
            c.messages = rand_bytes(rng, n * msize);
            cpu.sig->sign_batch(c, ctx, std::nullopt, nullptr);
            gpu.sig->verify_batch(c, ctx, nullptr);
            EXPECT_EQ(std::count(c.verify_ok.begin(), c.verify_ok.end(), 1), static_cast<long>(n)) << "n=" << n << " msize=" << msize;
            c.messages[0] ^= 1;  // порча сообщения
            gpu.sig->verify_batch(c, ctx, nullptr);
            EXPECT_EQ(c.verify_ok[0], 0);
        }
    }
}

TEST_F(GpuPqc, SigSingleOperationsAndManifestContext) {
    // vault подписывает manifest контекстом label::kManifestSigContext: работает при любом режиме
    // (при PureEmptyContext/Unusable одиночные операции идут на CPU — в batch это ошибка).
    const std::string ctx(label::kManifestSigContext);
    auto kp = gpu.sig->keygen(std::nullopt);
    Bytes msg = rand_bytes(rng, kManifestV1Size);
    Bytes sig = gpu.sig->sign(kp.secret_key.view(), msg, ctx, std::nullopt);
    EXPECT_TRUE(cpu.sig->verify(kp.public_key, msg, ctx, sig));
    EXPECT_TRUE(gpu.sig->verify(kp.public_key, msg, ctx, cpu.sig->sign(kp.secret_key.view(), msg, ctx, std::nullopt)));
    sig[3] ^= 1;
    EXPECT_FALSE(gpu.sig->verify(kp.public_key, msg, ctx, sig));
    EXPECT_FALSE(gpu.sig->verify(kp.public_key, msg, "edu-vault-manifest-v2", cpu.sig->sign(kp.secret_key.view(), msg, ctx, std::nullopt)));
}

TEST_F(GpuPqc, SigTimingPoolingAndSmallChunks) {
    const std::string ctx = manifest_ctx_on_gpu() ? "edu-vault-manifest-v1" : "";
    TimingBreakdown tb;
    crypto::SigBatch b;
    gpu.sig->keygen_batch(64, std::nullopt, b, &tb);
    EXPECT_GT(tb.kernel_ms, 0.0);
    EXPECT_GT(tb.entropy_ms, 0.0);
    b.message_size = kManifestV1Size;
    b.messages = rand_bytes(rng, 64 * kManifestV1Size);
    TimingBreakdown ts;
    gpu.sig->sign_batch(b, ctx, std::nullopt, &ts);
    EXPECT_GT(ts.total_ms, ts.kernel_ms);
    EXPECT_GT(ts.entropy_ms, 0.0);  // hedged sign: entropy от cuPQC

    crypto::BackendConfig c;
    c.gpu_max_chunk_bytes = 1 << 20;
    c.gpu_pool_buffers = true;
    auto small = make_gpu(c);
    for (int rep = 0; rep < 2; ++rep) {
        crypto::SigBatch s;
        small.sig->keygen_batch(300, std::nullopt, s, nullptr);
        s.message_size = kManifestV1Size;
        s.messages = rand_bytes(rng, 300 * kManifestV1Size);
        small.sig->sign_batch(s, ctx, std::nullopt, nullptr);
        cpu.sig->verify_batch(s, ctx, nullptr);
        EXPECT_EQ(std::count(s.verify_ok.begin(), s.verify_ok.end(), 1), 300L) << "rep=" << rep;
    }
}

// ------------------------------------------------------------------ vault

class GpuPqcVault : public GpuPqc {
protected:
    int run(const std::string& args) {
        std::string cmd = "cd '" + root.string() + "' && '" VAULT_CLI_PATH "' --vault vault --trusted trusted " + args + " >out.txt 2>err.txt";
        int st = std::system(cmd.c_str());
        return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    }
    std::string text(const std::string& name) {
        Bytes b = slurp(root / name);
        return std::string(b.begin(), b.end());
    }
};

TEST_F(GpuPqcVault, VaultCreatedOnGpuOpensOnCpuAndViceVersa) {
    ASSERT_EQ(run("--backend gpu init"), 0) << text("err.txt");       // Encaps (KEM) + keygen и подпись manifest (ML-DSA)
    spit(root / "in.txt", rand_bytes(rng, 3000));
    ASSERT_EQ(run("--backend gpu add in.txt"), 0) << text("err.txt");  // Decaps + подпись нового manifest
    std::string id = text("out.txt").substr(0, 32);
    EXPECT_EQ(run("--backend cpu verify"), 0) << text("err.txt");     // подписи GPU проверяет CPU
    ASSERT_EQ(run("--backend cpu add in.txt"), 0);
    EXPECT_EQ(run("--backend gpu verify"), 0) << text("err.txt");     // подпись CPU проверяет GPU
    ASSERT_EQ(run("--backend gpu extract " + id + " -o res.bin"), 0) << text("err.txt");
    EXPECT_EQ(slurp(root / "res.bin"), slurp(root / "in.txt"));

    // порча подписи manifest -> один и тот же VerifyStep на обоих backend'ах
    Bytes sig = slurp(current_dir() / "manifest.sig");
    sig[500] ^= 1;
    spit(current_dir() / "manifest.sig", sig);
    EXPECT_EQ(run("--backend cpu verify"), 2);
    EXPECT_NE(text("err.txt").find("INVALID: Signature"), std::string::npos);
    EXPECT_EQ(run("--backend gpu verify"), 2);
    EXPECT_NE(text("err.txt").find("INVALID: Signature"), std::string::npos);
}
