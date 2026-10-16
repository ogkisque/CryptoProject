// Эквивалентность backend'ов (этап 4.3): каждый доступный backend даёт те же байты, что reference (cpu).
// GPU-вариант включается автоматически, если сборка с CUDA и устройство есть (M5/M6).
#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include "vault/common/error.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/crypto/packed_batch.hpp"
#include "vault/merkle/merkle.hpp"

using namespace vault;
using namespace vault::crypto;

namespace {

std::vector<BackendConfig> available_backends() {
    std::vector<BackendConfig> v;
    BackendConfig mt;
    mt.kind = BackendKind::CpuParallel;
    mt.cpu_threads = 4;  // фиксировано, чтобы параллельные ветки выполнялись и на 1-ядерном CI
    v.push_back(mt);
    mt.cpu_threads = 0;  // hardware_concurrency
    v.push_back(mt);
    if (gpu_backend_compiled()) {
        BackendConfig g;
        g.kind = BackendKind::Gpu;
        try {
            make_backends(g);
            v.push_back(g);
        } catch (const VaultError&) {
        }
    }
    return v;
}

std::string param_name(const ::testing::TestParamInfo<BackendConfig>& i) {
    std::string s(to_string(i.param.kind));
    for (char& c : s)
        if (c == '-') c = '_';
    return s + "_t" + std::to_string(i.param.cpu_threads);
}

Bytes rand_bytes(std::mt19937_64& g, std::size_t n) {
    Bytes b(n);
    for (auto& x : b) x = static_cast<std::uint8_t>(g());
    return b;
}

}  // namespace

class BackendEquivalence : public ::testing::TestWithParam<BackendConfig> {
protected:
    BackendEquivalence() : ref(make_backends({})), under(make_backends(GetParam())), rng(12345) {}
    CryptoBackends ref, under;
    std::mt19937_64 rng;
};

TEST_P(BackendEquivalence, Sha3Batches) {
    for (std::size_t n : {0u, 1u, 2u, 17u, 300u}) {
        std::vector<Bytes> objs;
        for (std::size_t i = 0; i < n; ++i) objs.push_back(rand_bytes(rng, rng() % 5000));  // включая пустые
        if (n > 2) objs[n / 2] = rand_bytes(rng, 300000);                                     // перекос по размеру
        std::vector<ByteView> in(objs.begin(), objs.end());
        for (std::uint8_t dom : {std::uint8_t{0x00}, std::uint8_t{0x11}}) {
            std::vector<Hash256> a(n), b(n);
            ref.hash->domain_hash_batch(dom, in, a, nullptr);
            under.hash->domain_hash_batch(dom, in, b, nullptr);
            EXPECT_EQ(a, b) << "n=" << n;
            for (std::size_t i = 0; i < n; ++i) ASSERT_EQ(a[i], ref.hash->domain_hash(dom, in[i]));
        }
        std::vector<Hash256> a(n), b(n);
        ref.hash->sha3_256_batch(in, a, nullptr);
        under.hash->sha3_256_batch(in, b, nullptr);
        EXPECT_EQ(a, b);
        // упакованный формат даёт те же элементы
        PackedBatch packed = PackedBatch::pack(in);
        auto views = packed.views();
        std::vector<Hash256> c(n);
        under.hash->sha3_256_batch(views, c, nullptr);
        EXPECT_EQ(a, c);
    }
    EXPECT_EQ(ref.hash->sha3_256(as_view("abc")), under.hash->sha3_256(as_view("abc")));
}

TEST_P(BackendEquivalence, MerkleLeavesRootTreeAndProofs) {
    // 5000 и 9000 листьев: первые уровни шире порога параллельного подъёма.
    for (std::size_t n : {0u, 1u, 2u, 3u, 7u, 100u, 5000u, 9000u}) {
        std::vector<Bytes> objs;
        for (std::size_t i = 0; i < n; ++i) objs.push_back(rand_bytes(rng, 1 + rng() % 64));
        std::vector<ByteView> in(objs.begin(), objs.end());
        std::vector<Hash256> la(n), lb(n);
        ref.merkle->compute_leaves(in, la, nullptr);
        under.merkle->compute_leaves(in, lb, nullptr);
        ASSERT_EQ(la, lb) << "n=" << n;
        EXPECT_EQ(ref.merkle->root_from_leaves(la, nullptr), under.merkle->root_from_leaves(lb, nullptr)) << "n=" << n;
        auto ta = ref.merkle->build_tree(la, nullptr), tb = under.merkle->build_tree(lb, nullptr);
        EXPECT_EQ(ta.root, tb.root);
        ASSERT_EQ(ta.levels, tb.levels) << "n=" << n;
        if (n == 0) continue;

        std::vector<merkle::MerkleProof> proofs;
        std::vector<Hash256> pl;
        for (std::size_t i = 0; i < n; i += std::max<std::size_t>(1, n / 50)) {
            auto pa = merkle::make_proof(ta, i), pb = merkle::make_proof(tb, i);
            ASSERT_EQ(pa.steps.size(), pb.steps.size());
            for (std::size_t s = 0; s < pa.steps.size(); ++s) {
                EXPECT_EQ(pa.steps[s].kind, pb.steps[s].kind);
                EXPECT_EQ(pa.steps[s].sibling, pb.steps[s].sibling);
            }
            proofs.push_back(pb);
            pl.push_back(la[i]);
        }
        std::vector<std::uint8_t> ok_ref(proofs.size()), ok_under(proofs.size());
        ref.merkle->verify_proofs_batch(pl, proofs, ta.root, ok_ref, nullptr);
        under.merkle->verify_proofs_batch(pl, proofs, ta.root, ok_under, nullptr);
        EXPECT_EQ(ok_ref, ok_under);
        EXPECT_EQ(std::count(ok_under.begin(), ok_under.end(), 1), static_cast<long>(proofs.size()));
        pl[0][0] ^= 1;  // порча листа обнаруживается одинаково
        ref.merkle->verify_proofs_batch(pl, proofs, ta.root, ok_ref, nullptr);
        under.merkle->verify_proofs_batch(pl, proofs, ta.root, ok_under, nullptr);
        EXPECT_EQ(ok_ref, ok_under);
        EXPECT_EQ(ok_under[0], 0);
    }
}

TEST_P(BackendEquivalence, MlKemDeterministic) {
    const std::size_t n = 24;
    Bytes kseeds = rand_bytes(rng, n * kMlKem768KeygenSeedSize), mseeds = rand_bytes(rng, n * kMlKem768EncapsSeedSize);
    KemBatch a, b;
    ref.kem->keygen_batch(n, ByteView(kseeds), a, nullptr);
    under.kem->keygen_batch(n, ByteView(kseeds), b, nullptr);
    EXPECT_EQ(a.public_keys, b.public_keys);
    EXPECT_EQ(Bytes(a.secret_keys.view().begin(), a.secret_keys.view().end()),
              Bytes(b.secret_keys.view().begin(), b.secret_keys.view().end()));

    ref.kem->encaps_batch(a, ByteView(mseeds), nullptr);
    under.kem->encaps_batch(b, ByteView(mseeds), nullptr);
    EXPECT_EQ(a.ciphertexts, b.ciphertexts);
    EXPECT_EQ(Bytes(a.shared_secrets.view().begin(), a.shared_secrets.view().end()),
              Bytes(b.shared_secrets.view().begin(), b.shared_secrets.view().end()));
    Bytes ss_enc(b.shared_secrets.view().begin(), b.shared_secrets.view().end());

    ref.kem->decaps_batch(a, nullptr);
    under.kem->decaps_batch(b, nullptr);
    EXPECT_EQ(Bytes(a.shared_secrets.view().begin(), a.shared_secrets.view().end()),
              Bytes(b.shared_secrets.view().begin(), b.shared_secrets.view().end()));
    EXPECT_EQ(Bytes(b.shared_secrets.view().begin(), b.shared_secrets.view().end()), ss_enc);  // decaps == encaps

    // Одиночные операции
    ByteView s0 = ByteView(kseeds).subspan(0, kMlKem768KeygenSeedSize);
    auto k1 = ref.kem->keygen(s0), k2 = under.kem->keygen(s0);
    EXPECT_EQ(k1.public_key, k2.public_key);
    ByteView m0 = ByteView(mseeds).subspan(0, kMlKem768EncapsSeedSize);
    auto e1 = ref.kem->encaps(k1.public_key, m0), e2 = under.kem->encaps(k1.public_key, m0);
    EXPECT_EQ(e1.ciphertext, e2.ciphertext);
    auto d1 = ref.kem->decaps(k1.secret_key.view(), e1.ciphertext), d2 = under.kem->decaps(k1.secret_key.view(), e1.ciphertext);
    EXPECT_EQ(Bytes(d1.view().begin(), d1.view().end()), Bytes(d2.view().begin(), d2.view().end()));
}

TEST_P(BackendEquivalence, MlDsaDeterministic) {
    const std::size_t n = 12;
    Bytes seeds = rand_bytes(rng, n * kMlDsa65KeygenSeedSize), rnds(n * kMlDsa65SignRandSize, 0);  // 0^32 = детерминированно
    SigBatch a, b;
    ref.sig->keygen_batch(n, ByteView(seeds), a, nullptr);
    under.sig->keygen_batch(n, ByteView(seeds), b, nullptr);
    EXPECT_EQ(a.public_keys, b.public_keys);
    EXPECT_EQ(Bytes(a.secret_keys.view().begin(), a.secret_keys.view().end()),
              Bytes(b.secret_keys.view().begin(), b.secret_keys.view().end()));

    a.message_size = b.message_size = kManifestV1Size;
    a.messages = b.messages = rand_bytes(rng, n * kManifestV1Size);
    ref.sig->sign_batch(a, "edu-vault-manifest-v1", ByteView(rnds), nullptr);
    under.sig->sign_batch(b, "edu-vault-manifest-v1", ByteView(rnds), nullptr);
    EXPECT_EQ(a.signatures, b.signatures);

    ref.sig->verify_batch(a, "edu-vault-manifest-v1", nullptr);
    under.sig->verify_batch(b, "edu-vault-manifest-v1", nullptr);
    EXPECT_EQ(a.verify_ok, b.verify_ok);
    EXPECT_EQ(std::count(b.verify_ok.begin(), b.verify_ok.end(), 1), static_cast<long>(n));

    // Порча: оба backend'а отвергают одно и то же.
    b.signatures[3 * kMlDsa65SignatureSize + 17] ^= 1;
    b.messages[7 * b.message_size] ^= 1;
    a.public_keys = b.public_keys;
    a.messages = b.messages;
    a.signatures = b.signatures;
    ref.sig->verify_batch(a, "edu-vault-manifest-v1", nullptr);
    under.sig->verify_batch(b, "edu-vault-manifest-v1", nullptr);
    EXPECT_EQ(a.verify_ok, b.verify_ok);
    EXPECT_EQ(b.verify_ok[3], 0);
    EXPECT_EQ(b.verify_ok[7], 0);
    EXPECT_EQ(std::count(b.verify_ok.begin(), b.verify_ok.end(), 1), static_cast<long>(n - 2));

    // Одиночные sign/verify, hedged-подпись проходит проверку на обоих
    auto kp = under.sig->keygen(std::nullopt);
    Bytes msg(168, 5);
    Bytes sig = under.sig->sign(kp.secret_key.view(), msg, "ctx", std::nullopt);
    EXPECT_TRUE(ref.sig->verify(kp.public_key, msg, "ctx", sig));
    EXPECT_TRUE(under.sig->verify(kp.public_key, msg, "ctx", sig));
}

INSTANTIATE_TEST_SUITE_P(Backends, BackendEquivalence, ::testing::ValuesIn(available_backends()), param_name);
